import binascii
import hashlib
from enum import Enum
from logging import getLogger
import ssl
import socket
from typing import Any, Optional
from urllib.parse import urljoin

import requests
import urllib3


LOGGER = getLogger(__name__)


class Client:
    class Dataset(Enum):
        USER_TYPE = "user_type"
        # {'UserType': '1'}

        SYSTEM_MODEL = "system_model"
        # {'modelName': 'CGNV4-FX4', 'skipWizard': '1'}

        SYSINFO = "getSysInfo"
        # [{'LRecPkt': '12.12M Bytes',
        #   'LSendPkt': '40.14M Bytes',
        #   'WRecPkt': '40.25M Bytes',
        #   'WSendPkt': '11.77M Bytes',
        #   'aftrAddr': '',
        #   'aftrName': '',
        #   'delegatedPrefix': '',
        #   'hwVersion': '2D',
        #   'lanIPv6Addr': '',
        #   'lanIp': '192.0.2.0/24',
        #   'rfMac': '84:0B:7C:01:02:03',
        #   'serialNumber': 'ABC123',
        #   'swVersion': '4.5.10.201-CD-UPC',
        #   'systemTime': 'Fri Jun 17, 2022, 17:09:10',
        #   'systemUptime': '00 Days,05 Hours,38 Minutes,47 Seconds',
        #   'timezone': '1',
        #   'wanIp': '203.0.113.1/24'}]

        CMINIT = "getCMInit"
        # [{'bpiStatus': 'AUTH:authorized, TEK:operational',
        #   'dhcp': 'Success',
        #   'downloadCfg': 'Success',
        #   'eaeStatus': 'Secret',
        #   'findDownstream': 'Success',
        #   'hwInit': 'Success',
        #   'networkAccess': 'Permitted',
        #   'ranging': 'Success',
        #   'registration': 'Success',
        #   'timeOfday': 'Secret',
        #   'trafficStatus': 'Enable'}]

        DSINFO = "dsinfo"
        # [{'channelId': '9',
        #   'frequency': '426250000',
        #   'modulation': '2',
        #   'portId': '1',
        #   'signalStrength': '17.400',
        #   'snr': '40.946'},
        #  ...]

        CMDOCSISWAN = "getCmDocsisWan"
        # [{'CmGateway': '10.252.220.1',
        #  'CmIpAddress': '10.252.220.125',
        #  'CmIpLeaseDuration': '04 Days,09 Hours,47 Minutes,10 '
        #                       'Seconds',
        #  'CmNetMask': '255.255.252.0',
        #  'Configname': 'Secret',
        #  'NetworkAccess': 'Permitted'}],

        USINFO = "usinfo"
        # [{'bandwidth': '6400000',
        #   'channelId': '2',
        #   'frequency': '39400000',
        #   'portId': '1',
        #   'scdmaMode': 'ATDMA',
        #   'signalStrength': '36.000'},
        #  ...]

        CONNECTINFO = "getConnectInfo"
        # [{'comnum': 1,
        #   'connectType': 'Self-assigned',
        #   'hostName': 'Unknown',
        #   'id': 4,
        #   'interface': 'Ethernet',
        #   'ipAddr': '192.0.2.16',
        #   'ipType': 'IPv4',
        #   'macAddr': '76:77:47:AE:A0:A1',
        #   'online': 'active'},
        #  ...]

        TUNEFREQ = "getTuneFreq"
        # [{'tunefreq': '426.250'}]

        def path(self) -> str:
            return f"data/{self.value}.asp"

    def __init__(self, host: str, fingerprint: Optional[str]) -> None:
        self.__base_url = f"https://{host}/"

        if not fingerprint:
            LOGGER.warn(
                (
                    "Communication with <%s> is insecure because the TLS server"
                    " certificate fingerprint was not specified."
                ),
                host,
            )
            LOGGER.warn(
                "Fingerprint of <%s> is %s",
                host,
                get_server_certificate_fingerprint((host, 443), timeout=5),
            )

        self.__session = requests.Session()
        self.__session.mount(self.__base_url, HitronHTTPAdapter(fingerprint))

    def login(self, usr: str, pwd: str, force: bool = False) -> None:
        r = self.__session.get(
            self.__base_url, allow_redirects=False, verify=False, timeout=2
        )
        r.raise_for_status()
        assert "preSession" in self.__session.cookies

        r = self.__session.post(
            urljoin(self.__base_url, "goform/login"),
            allow_redirects=False,
            verify=False,
            timeout=10,
            data={
                "usr": usr,
                "pwd": pwd,
                "forcelogoff": "0" if not force else "1",
                "preSession": self.__session.cookies["preSession"],
            },
        )
        r.raise_for_status()

        if r.text == "success":
            return
        else:
            raise RuntimeError(r.text)

    def get_data(self, dataset: Dataset) -> Any:
        r = self.__session.get(
            urljoin(self.__base_url, dataset.path()),
            allow_redirects=False,
            verify=False,
            timeout=2,
        )
        r.raise_for_status()
        if r.status_code != 200:
            raise PermissionError("Not logged in")
        return r.json()

    def logout(self) -> None:
        r = self.__session.post(
            urljoin(self.__base_url, "goform/logout"),
            allow_redirects=False,
            verify=False,
            timeout=2,
            data={"data": "byebye"},
        )
        r.raise_for_status()


# We can't use ssl.get_server_certificate because it hardcodes an SSLContext
# that is not lenient enough.
def get_server_certificate_fingerprint(addr: tuple[str, int], timeout: int) -> str:
    ctx = HitronHTTPAdapter.create_context()
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(addr, timeout=timeout) as sock:
        with ctx.wrap_socket(sock) as sslsock:
            crt = sslsock.getpeercert(True)
            if not crt:
                raise RuntimeError(
                    "TLS server certificate missing; this should not be possible!"
                )
            digest = hashlib.sha256(crt).digest()
            return binascii.hexlify(digest, ":").decode("ascii")


class HitronHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Relaxes potential default OpenSSL configuration to allow communication with
    the cable modem (which uses a 1024-bit RSA key, rejected by modern OpenSSL
    configurations).

    Verifies the cable modem's TLS server certificate against the specified
    fingerprint. The fingerprint may be produced from the certificate with the
    command:

    openssl x509 -in cert.crt -noout -sha256 -fingerprint
    """

    def __init__(self, fingerprint: Optional[str], **kwargs: Any) -> None:
        self.__fingerprint = fingerprint
        self.__context = HitronHTTPAdapter.create_context()

        super().__init__(**kwargs)

    @classmethod
    def create_context(klass) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        return ctx

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **kwargs: Any,
    ) -> None:
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            assert_fingerprint=self.__fingerprint,
            ssl_context=self.__context,
            **kwargs,
        )
