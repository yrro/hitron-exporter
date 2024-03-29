import binascii
from enum import Enum
import hashlib
import http.cookiejar
import json
from logging import getLogger
import ssl
import socket
from typing import Any, Optional
from urllib.parse import urljoin
import urllib.request

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

    def __init__(self, host: str, fingerprint: Optional[str], port: int = 443) -> None:
        self.__base_url = f"https://{host}:{port}/"
        ssl_context = self.__create_ssl_context()

        if not fingerprint:
            LOGGER.warning(
                (
                    "Communication with <%s> is insecure because the expected TLS"
                    " server certificate fingerprint was not specified. The host"
                    " presented a certificate with the following fingerprint: %r"
                ),
                self.__base_url,
                _get_server_certificate_fingerprint((host, port), 5, ssl_context),
            )

        self.__http = urllib3.PoolManager(
            timeout=5.0,
            assert_fingerprint=fingerprint,
            ssl_context=ssl_context,
        )
        self.__cookies = http.cookiejar.CookieJar()

    @staticmethod
    def __create_ssl_context() -> ssl.SSLContext:
        """
        An SSLContext for communication with the cable modem which uses a 1024-bit RSA
        key, rejected by modern OpenSSL configurations.
        """
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        return ctx

    def http_request(
        self,
        method: Any,
        url: Any,
        fields: Any = None,
        headers: Any = None,
    ) -> Any:
        """
        urllib3 wrapper that uses a CookieJar to provide rudimentary cookie handling.
        """
        dummy_request = urllib.request.Request(
            url, headers=headers if headers is not None else {}
        )
        self.__cookies.add_cookie_header(dummy_request)

        # After a redirect to another host, prevent leaking cookies intended only for
        # the original host. We do this by setting retries=False because we also want to
        # disable retry logic, causing any thown exceptions to be their original
        # instances and not wrapped by MaxRetryError.
        response = self.__http.request(
            method,
            url,
            fields=fields,
            headers=dict(dummy_request.header_items()),
            retries=False,
        )  # type: ignore [no-untyped-call]
        self.__cookies.extract_cookies(response, dummy_request)
        return response

    def login(self, usr: str, pwd: str, force: bool = False) -> None:
        # / sets a preSession cookie that must be included in the POST to the login form
        # to avoid a 'session timeout expired' error

        r = self.http_request(
            "GET",
            self.__base_url,
        )

        try:
            presession_cookie = next(
                (c for c in self.__cookies if c.name == "preSession"),
            )
        except StopIteration:
            raise RuntimeError("preSession cookie not in jar") from None

        r = self.http_request(
            "POST",
            urljoin(self.__base_url, "goform/login"),
            fields={
                "usr": usr,
                "pwd": pwd,
                "forcelogoff": "0" if not force else "1",
                presession_cookie.name: presession_cookie.value,
            },
        )
        if r.status != 200:
            raise AssertionError(f"Unexpected login response status: {r.status!r}")

        # If another session is active then the response data will be b"Repeat Login"
        if r.data != b"success":
            # Observed error messages:
            #   b"Repeat Login"
            #   b"Wrong Credentials."
            raise RuntimeError(r.data.decode("ascii"))

    def get_data(self, dataset: Dataset) -> Any:
        r = self.http_request(
            "GET",
            urljoin(self.__base_url, dataset.path()),
        )
        if r.status == 302:
            raise RuntimeError("Not logged in")
        if r.status != 200:
            raise AssertionError(f"Unexpected data response status: {r.status!r}")
        if r.headers["Content-Type"] != "application/json":
            raise AssertionError(
                f"Unexpected data response content-type: {r.headers['Content-Type']!r}"
            )
        return json.loads(r.data)

    def logout(self) -> None:
        r = self.http_request(
            "POST",
            urljoin(self.__base_url, "goform/logout"),
            fields={"data": "byebye"},
        )
        if r.status != 302:
            raise AssertionError(f"Unexpected logout response status: {r.status!r}")


def _get_server_certificate_fingerprint(
    addr: tuple[str, int], timeout: int, ssl_context: ssl.SSLContext
) -> str:
    """
    Ideally we'd call ssl.get_server_certificate, but that function
    does not provide a way for us to provide our own SSLContext, so
    we have to re-implement it.
    """
    with socket.create_connection(addr, timeout=timeout) as sock:
        with ssl_context.wrap_socket(sock) as sslsock:
            crt = sslsock.getpeercert(binary_form=True)
            if not crt:
                raise AssertionError(
                    "for a client SSL socket, the server will always provide a"
                    " certificate, regardless of whether validation was required"
                )
            digest = hashlib.sha256(crt).digest()
            return binascii.hexlify(digest, ":").decode("ascii")
