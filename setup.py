import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="napalm-aruba-switch-api-esk",
    version="0.0.1",
    author="Eldon Koyle",
    authon_email="ekoyle@gmail.com",
    description="NAPALM driver for HPE/Aruba switches using rest-api",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ekoyle/napalm-aruba-switch-api",
    pacakges=setuptools.find_packages(),
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python :: 3",
        "OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)"
        "Operating System :: OS Independent",
    ],
    python_requires="~=3.4",
    install_requires=["requests>=2.12.0"],
)
