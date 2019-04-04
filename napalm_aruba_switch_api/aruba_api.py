from napalm.base.base import NetworkDriver
import requests
import os
import base64


class ArubaSwitchApiClient(object):
    def __init__(self, transport, hostname, port, username, password):
        self.cookies = {}
        self._headers = {"Accept": "application/json"}
        self.baseurl = None
        self.hostname = hostname
        self.transport = transport
        self.port = port
        self.username = username
        self.password = password

    def _get_url(self, relative_path):
        url = os.path.join(self.baseurl, relative_path)
        return url

    def _do_request(self, method, relative_path, data=None, raise_on_error=True):
        url = self._get_url(relative_path)
        args = {'url': url,
                'cookies': self.cookies,
                'headers': self._headers}
        if data:
            args['json'] = data
        r = method(**args)
        if raise_on_error and not r.ok:
            print(r.request.__dict__)
            print(r.text)
            r.raise_for_status()
        return r

    def check_session(self):
        if not self.baseurl:
            return False

        # FIXME: find a better function
        r = self._do_request(requests.get, "login-sessions",
                             raise_on_error=False)
        if not r.ok and "timed out" in r.text:
            return False
        return True

    def _login_if_session_expired(self):
        if not self.check_session():
            self._do_relogin()

    def _do_relogin(self):
        r = self._do_request(requests.post,
                             "login-sessions",
                             data={'userName': self.username,
                                   'password': self.password})
        k, v = r.json()['cookie'].split('=', 1)
        self.cookies[k] = v

    def login(self):
        if self.baseurl:
            return self._do_relogin()

        self.baseurl = "{}://{}:{}/rest".format(self.transport,
                                                self.hostname,
                                                self.port)
        r = self._do_request(requests.post,
                             "v1/login-sessions",
                             data={'userName': self.username,
                                   'password': self.password})

        k, v = r.json()['cookie'].split('=', 1)
        self.cookies[k] = v

        version = self._do_request(requests.get, "version")

        for v in version.json()['version_element']:
            if v['version'] == 'v5.0':
                self.baseurl = os.path.join(self.baseurl, v['version'])
                break
        else:
            raise Exception("API v5.0 not supported")

    def logout(self):
        if not self.baseurl:
            return

        if self.check_session():
            self._do_request(requests.delete,
                             'login-sessions')
        self.baseurl = None
        self.cookies = {}

    def cli(self, command):
        r = self._do_request(requests.post,
                             "cli",
                             data={"cmd": command})
        r = r.json()
        if r['status'] != 'CCS_SUCCESS':
            raise Exception("Command failed: {}: {}".format(r['status'],
                                                            r['error_msg']))
        output = r['result_base64_encoded']
        output = base64.b64decode(output)
        return output.decode(encoding='utf-8')

    def cli_bulk(self, commands):
        """Note: only config commands?"""
        raise Exception("untested, incomplete implementation")
        b64_commands = base64.b64encode(commands)
        r = self._do_request(requests.post,
                             "cli_bulk",
                             data={"cli_batch_base64_encoded": b64_commands})
        # FIXME: watch for completion, then get logs?
        return r.decode(encoding="utf-8")

    def config_payload(self, config, payload_type):
        assert payload_type in ('RPT_PATCH_FILE', 'RPT_BACKUP_FILE', )

        config_base64 = base64.b64encode(config)
        path = "system/config/payload"

        r = self._do_request(requests.post,
                             path,
                             data={"config_base64_encoded": config_base64,
                                   "payload_type": payload_type})

        r = self._do_check_status(path, r)

        status = r.json()['status']
        if status != 'CRS_SUCCESS':
            raise Exception("config payload failed: {}".format(status))
        return r

    def config_restore(self, forced_reboot=False, recoverymode=True):
        file_name = "REST_Payload_Backup"
        path = "system/config/cfg_restore"
        r = self._do_request(requests.post,
                             path,
                             data={"server_type": "ST_FLASH",
                                   "file_name": file_name,
                                   "is_forced_reboot_enabled": forced_reboot,
                                   "is_recoverymode_enabled": recoverymode})
        r = self._do_check_status(path, r)
        return r

    def config_restore_diff(self):
        file_name = "REST_Payload_Backup"
        path = "system/config/cfg_restore/latest_diff"
        r = self._do_request(requests.post,
                             path,
                             data={"server_type": "ST_FLASH",
                                   "file_name": file_name})
        r = self._do_check_status(path, r)
        return r

    def _do_check_status(self, relative_path, request):
        # for some reason, commands with a /status seem to kill our session
        self._login_if_session_expired()
        if request.json()['status'] != "CRS_IN_PROGRESS":
            return request
        poll_path = os.path.join(relative_path, 'status')
        r = self._do_request(requests.get, poll_path)
        return r


class ArubaSwitchApiDriver(NetworkDriver):
    def __init__(self,
                 hostname,
                 username,
                 password,
                 timeout=60,
                 optional_args=None):

        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.transport = optional_args.get('protocol', 'http')
        self._api = ArubaSwitchApiClient(transport=self.transport,
                                         hostname=self.hostname,
                                         port=optional_args.get('port', 80),
                                         username=self.username,
                                         password=self.password)

    def _strip_config(self, config):
        # strip off the non-config parts returned by show run/show config
        # as well as the trailing null
        begin = config.find(';')
        if config[-1] == '\0':
            return config[begin:-1]
        return config[begin:]

    def get_config(self, retrieve=u'all'):
        running = startup = candidate = ''

        if retrieve in ['all', 'running']:
            running = self._api.cli("show running-config")
            running = self._strip_config(running)

        if retrieve in ['all', 'startup']:
            startup = self._api.cli("show config")
            startup = self._strip_config(startup)

        if retrieve in ['all', 'candidate']:
            # There is no "candidate"-like config if we haven't done a
            # "load_replace_candidate()", and all bets are off with a
            # "load_merge_candidate()" -- FIXME: what to do here?
            # candidate = self._api.cli("show config REST_Config_Backup"
            pass

        return {'running': running, 'startup': startup, 'candidate': candidate}

    def open(self):
        self._api.login()

    def close(self):
        self._api.logout()

    def is_alive(self):
        return self._api.check_session()

    def get_facts(self):
        super().get_facts()
        # uptime
        # vendor
        # os_version
        # serial_number
        # model
        # hostname
        # fqdn
        # interface_list
        return

    def cmd(self, commands):
        result = {}
        for command in commands:
            result['command'] = self._api.cli(command)
        return result
