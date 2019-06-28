from napalm.base.base import NetworkDriver
import requests
import os
import base64
import re

SECONDS_IN_DAY = 86400
SECONDS_IN_HOUR = 3600
SECONDS_IN_MINUTE = 60


def parse_snmp(text):
    value = text.split(" = ", 1)[1]
    return value


def parse_uptime(text):
    d, h, m, s = text.strip().split(":")
    days_s = int(d, 10) * SECONDS_IN_DAY
    hours_s = int(h, 10) * SECONDS_IN_HOUR
    minutes_s = int(m, 10) * SECONDS_IN_MINUTE
    seconds = float(s)

    return days_s + hours_s + minutes_s + seconds


def parse_snmp_list(text):
    lines = []
    for line in text.strip().split("\n"):
        lines.append(parse_snmp(line))

    return lines


def parse_int_brief(text):
    lines = text.strip().split("\n")
    lines = list(lines)

    ports = []

    if "third-party transceiver" in lines[-1]:
        del lines[-1]

    # delete all the header foo
    while "------" not in lines[0]:
        del lines[0]
    del lines[0]

    for line in lines:
        port = line.split(None, 1)[0].strip()
        ports.append(port)

    return ports


def parse_sysdescr(sysdescr):
    s = sysdescr

    m = re.search(r"Aruba (\S+) (\S+) Switch", s)  # new Aruba-branded switches
    if m:
        model = "%s (%s)" % (m.group(2), m.group(1))
        vendor = "Aruba"
        return (vendor, model)

    m = re.search(r"ProCurve (\S+) Switch (\S+)", s)
    if m:
        model = "%s (%s)" % (m.group(2).strip(","), m.group(1))
        vendor = "Hewlett Packard (ProCurve)"
        return (vendor, model)

    m = re.search(r"(\S+) ProCurve Switch (\S+)", s)  # older switches
    if m:
        model = "%s (%s)" % (m.group(2).strip(","), m.group(1))
        vendor = "Hewlett Packard (ProCurve)"
        return (vendor, model)

    raise Exception("Failed to parse model from sysDescr")


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

    def __del__(self):
        self.logout()
        return super()

    def _get_url(self, relative_path):
        url = os.path.join(self.baseurl, relative_path)
        return url

    def _do_request(self, method, relative_path, data=None, raise_on_error=True):
        url = self._get_url(relative_path)
        args = {"url": url, "cookies": self.cookies, "headers": self._headers}
        if data:
            args["json"] = data
        r = method(**args)
        if raise_on_error and not r.ok:
            raise requests.HTTPError(
                "{} {}: URL: {} data: {}".format(r.status_code, r.reason, r.url, r.text)
            )
            r.raise_for_status()
        return r

    def check_session(self):
        if not self.baseurl:
            return False

        # FIXME: find a better function
        r = self._do_request(requests.get, "login-sessions", raise_on_error=False)
        if not r.ok and "timed out" in r.text:
            return False
        return True

    def _login_if_session_expired(self):
        if not self.check_session():
            self._do_relogin()

    def _do_relogin(self):
        r = self._do_request(
            requests.post,
            "login-sessions",
            data={"userName": self.username, "password": self.password},
        )
        k, v = r.json()["cookie"].split("=", 1)
        self.cookies[k] = v

    def login(self):
        if self.baseurl:
            return self._do_relogin()

        self.baseurl = "{}://{}:{}/rest".format(
            self.transport, self.hostname, self.port
        )
        r = self._do_request(
            requests.post,
            "v1/login-sessions",
            data={"userName": self.username, "password": self.password},
        )

        k, v = r.json()["cookie"].split("=", 1)
        self.cookies[k] = v

        version = self._do_request(requests.get, "version")

        for v in version.json()["version_element"]:
            if v["version"] == "v5.0":
                self.baseurl = os.path.join(self.baseurl, v["version"])
                break
        else:
            raise Exception("API v5.0 not supported")

    def logout(self):
        if not self.baseurl:
            return

        if self.check_session():
            self._do_request(requests.delete, "login-sessions")
        self.baseurl = None
        self.cookies = {}

    def cli(self, command):
        r = self._do_request(requests.post, "cli", data={"cmd": command})
        r = r.json()
        if r["status"] != "CCS_SUCCESS":
            raise Exception(
                "Command failed: {}: {}".format(r["status"], r["error_msg"])
            )
        output = r["result_base64_encoded"]
        output = base64.b64decode(output)
        output = output.decode(encoding="utf-8").strip("\0")
        return output

    def cli_bulk(self, commands):
        """Note: only config commands?"""
        raise Exception("untested, incomplete implementation")
        b64_commands = base64.b64encode(commands).decode("ascii")
        r = self._do_request(
            requests.post, "cli_bulk", data={"cli_batch_base64_encoded": b64_commands}
        )
        # FIXME: watch for completion, then get logs?
        return r.decode(encoding="utf-8")

    def config_payload(self, config, payload_type):
        assert payload_type in ("RPT_PATCH_FILE", "RPT_BACKUP_FILE")

        config_base64 = base64.b64encode(config.encode("utf-8")).decode("ascii")
        path = "system/config/payload"

        r = self._do_request(
            requests.post,
            path,
            data={"config_base64_encoded": config_base64, "payload_type": payload_type},
        )

        r = self._do_check_status(path, r)

        r = r.json()

        status = r["status"]
        if status != "CRS_SUCCESS":
            raise Exception("config payload failed: {}".format(status))

        return r

    def config_restore(
        self,
        file_name="REST_Payload_Backup",
        server_type="ST_FLASH",
        tftp_server_address=None,
        sftp_server_address=None,
        forced_reboot=False,
        recoverymode=True,
    ):
        path = "system/config/cfg_restore"
        assert server_type in ("ST_FLASH", "ST_TFTP", "ST_SFTP")

        data = {
            "server_type": server_type,
            "file_name": file_name,
            "is_forced_reboot_enabled": forced_reboot,
            "is_recoverymode_enabled": recoverymode,
        }

        if server_type == "ST_TFTP":
            assert tftp_server_address is not None
            data["tftp_server_address"] = tftp_server_address
        else:
            assert tftp_server_address is None

        if server_type == "ST_SFTP":
            assert sftp_server_address is not None
            data["sftp_server_address"] = sftp_server_address
        else:
            assert sftp_server_address is None

        r = self._do_request(
            requests.post,
            path,
            data={
                "server_type": server_type,
                "file_name": file_name,
                "is_forced_reboot_enabled": forced_reboot,
                "is_recoverymode_enabled": recoverymode,
            },
        )
        r = self._do_check_status(path, r)
        return r

    def config_restore_diff(self):
        file_name = "REST_Payload_Backup"
        path = "system/config/cfg_restore/latest_diff"
        r = self._do_request(
            requests.post,
            path,
            data={"server_type": "ST_FLASH", "file_name": file_name},
        )
        r = self._do_check_status(path, r)
        return r

    def _do_check_status(self, relative_path, request):
        # for some reason, commands with a /status seem to kill our session
        self._login_if_session_expired()
        if request.json()["status"] != "CRS_IN_PROGRESS":
            return request
        poll_path = os.path.join(relative_path, "status")
        r = self._do_request(requests.get, poll_path)
        return r


class ArubaSwitchApiDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.transport = optional_args.get("protocol", "http")
        self._api = ArubaSwitchApiClient(
            transport=self.transport,
            hostname=self.hostname,
            port=optional_args.get("port", 80),
            username=self.username,
            password=self.password,
        )
        self._load_type = None

    def _strip_config(self, config):
        # strip off the non-config parts returned by show run/show config
        # as well as the trailing null
        begin = config.find(";")
        return config[begin:]

    def get_config(self, retrieve=u"all"):
        running = startup = candidate = ""

        if retrieve in ["all", "running"]:
            running = self._api.cli("show running-config")
            running = self._strip_config(running)

        if retrieve in ["all", "startup"]:
            startup = self._api.cli("show config")
            startup = self._strip_config(startup)

        if retrieve in ["all", "candidate"]:
            # There is no "candidate"-like config if we haven't done a
            # "load_replace_candidate()", and all bets are off with a
            # "load_merge_candidate()" -- FIXME: what to do here?
            # candidate = self._api.cli("show config REST_Config_Backup"
            pass

        return {"running": running, "startup": startup, "candidate": candidate}

    def open(self):
        self._api.login()

    def close(self):
        self._api.logout()

    def is_alive(self):
        return self._api.check_session()

    def get_facts(self):
        # So... we have this API, but it doesn't actually help with collecting
        # data... so let's just run CLI commands via the API... including our
        # CLI command to return SNMP data (I mean... I guess it's easy to
        # parse...)

        # uptime
        uptime = parse_uptime(self._api.cli("show uptime"))
        # vendor
        # model
        sysDescr = self._api.cli("walkMIB sysDescr")
        (vendor, model) = parse_sysdescr(sysDescr)
        # os_version
        os_version = parse_snmp(self._api.cli("walkMIB hpHttpMgVersion"))
        # serial_number
        serial = parse_snmp(self._api.cli("walkMIB hpHttpMgSerialNumber"))
        # hostname # FIXME: don't know where to find this without munging config
        # fqdn
        hostname = fqdn = parse_snmp(self._api.cli("walkMIB sysName"))
        # interface_list
        # ** found a bug -- API displays header/footer but no int on sh int bri
        # interfaces = parse_int_brief(self._api.cli('show interfaces brief all'))
        interfaces = parse_snmp_list(self._api.cli("walkMIB ifName"))

        facts = {
            "uptime": uptime,
            "vendor": vendor,
            "model": model,
            "os_version": os_version,
            "serial_number": serial,
            "hostname": hostname,
            "fqdn": fqdn,
            "interface_list": interfaces,
        }

        return facts

    def cli(self, commands):
        result = {}
        for command in commands:
            result["command"] = self._api.cli(command)
        return result

    def commit_config(self, message=u"", forced_reboot=False, recoverymode=True):
        if message:
            raise NotImplementedError("Commit message not supported on this platform")
        if self._load_type == "patch":
            raise NotImplementedError("not sure what to do with these")
        elif self._load_type == "replace":
            self._api.config_restore(
                forced_reboot=forced_reboot, recoverymode=recoverymode
            )
            return
        raise ValueError("Must call load_(replace|merge)_candidate")

    def load_replace_candidate(self, filename=None, config=None):
        if filename:
            with open(filename) as f:
                config = f.read()
        if not config:
            raise ValueError("Must specify config or filename")
        r = self._api.config_payload(config, "RPT_BACKUP_FILE")
        self._load_type = "replace"
        return r

    def load_merge_candidate(self, filename=None, config=None):
        raise NotImplementedError("'patch' format not documented, untested")
        # Not sure what "PATCH_FILE" means... maybe this is something else? :/
        if filename:
            with open(filename) as f:
                config = f.read()
        if not config:
            raise ValueError("Must specify config or filename")
        r = self._api.config_payload(config, "RPT_PATCH_FILE")
        self._load_type = "patch"
        return r

    def discard_config(self):
        if self._load_type == "patch":
            raise NotImplementedError("'patch' format not documented")
            self._load_type = None
        elif self._load_type == "replace":
            self._api.cli("delete REST_Payload_Backup")
            self._load_type = None
        raise ValueError("No config has been loaded to discard")
