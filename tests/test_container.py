import binascii
import hashlib
import json
import logging
import ssl
import subprocess
import time

import pytest
import trustme
import urllib3
from werkzeug.wrappers import Request, Response

from .conftest import suite

pytestmark = suite("container")

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def ca():
    return trustme.CA()


@pytest.fixture(scope="session")
def hitron_cert(ca):
    # The real web server's TLS server certificate has no Subject Alternative Name
    # values, and a subject of:
    # CN=02:00:00:00:00:00,OU=No. 40\, Wu-kung 5th Rd.\, Wu-ku\, Taipei Hsien\, Taiwan,O=Hitron Technologies,C=TW
    return ca.issue_cert(common_name="02:00:00:00:00:00")


@pytest.fixture(scope="session")
def httpserver_ssl_context(hitron_cert):
    """
    This fixture causes pytest_httpserver to become an HTTPS server."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    hitron_cert.configure_cert(context)
    return context


def image_default_args(image: str) -> str:
    p0 = subprocess.run(
        ["podman", "image", "inspect", "localhost/hitron-exporter"],
        stdout=subprocess.PIPE,
        text=True,
    )
    if p0.returncode != 0:
        pytest.fail("Couldn't inspect container image")

    image_inspect = json.loads(p0.stdout)
    try:
        return next(
            (
                e
                for e in image_inspect[0]["Config"]["Env"]
                if e.startswith("GUNICORN_CMD_ARGS=")
            ),
        )
    except StopIteration:
        pytest.fail("Couldn't find GUNICORN_CMD_ARGS in image environment")


@pytest.fixture(scope="module")
def container():
    default_args = image_default_args("localhost/hitron-exporter")
    p = subprocess.run(
        [
            "podman",
            "run",
            "-d",
            "--rm",
            "--pull=never",
            "--network=slirp4netns:allow_host_loopback=true",
            "--publish=127.0.0.1::9938",
            f"--env={default_args} --log-level=debug",
            "localhost/hitron-exporter",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        pytest.fail("Couldn't start container")
    ctr = p.stdout.rstrip()

    try:
        p2 = subprocess.run(
            ["podman", "port", ctr, "9938/tcp"],
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        )
        host, sep, port_ = p2.stdout.rstrip().partition(":")
        addr = (host, int(port_))

        # XXX no better way to wait for conatiner readiness?
        time.sleep(2)

        yield addr
    finally:
        p3 = subprocess.run(
            ["podman", "logs", ctr],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        logger.info("----- BEGIN CONTAINER LOGS ----")
        for line in p3.stdout.split("\n"):
            if line:
                logger.info("%s", line)
        logger.info("----- END CONTAINER LOGS ----")
        subprocess.run(["podman", "stop", ctr], stdout=subprocess.DEVNULL, check=True)


def test_metrics(container):
    # given:
    http = urllib3.PoolManager(retries=False)
    url = f"http://{container[0]}:{container[1]}/metrics"

    # when:
    r = http.request("GET", url)

    # then:
    assert r.status == 200


@pytest.fixture
def hitron_server(httpserver):
    """
    Note: to see the logs of the mock Hitron web server, run pytest with
    --log-level=DEBUG.
    """
    httpserver.expect_request("/", method="GET").respond_with_data(
        "",
        status=302,
        headers={
            "Set-Cookie": "preSession=presession_id; path=/",
            "Location": httpserver.url_for("/login.html"),
        },
    )

    def login_handler(request: Request) -> Response:
        assert request.form.get("usr") == "uuu"
        assert request.form.get("pwd") == "ppp"
        assert request.form.get("preSession") == "presession_id"
        return Response(
            "success", headers={"Set-Cookie": "session=sessionid; path=/; HttpOnly"}
        )

    httpserver.expect_request("/goform/login", method="POST").respond_with_handler(
        login_handler
    )

    data = {
        "system_model": {"modelName": "CGNV4-FX4", "skipWizard": "1"},
        "getSysInfo": [
            {
                "LRecPkt": "12.12M Bytes",
                "LSendPkt": "40.14M Bytes",
                "WRecPkt": "40.25M Bytes",
                "WSendPkt": "11.77M Bytes",
                "aftrAddr": "",
                "aftrName": "",
                "delegatedPrefix": "",
                "hwVersion": "2D",
                "lanIPv6Addr": "",
                "lanIp": "192.0.2.0/24",
                "rfMac": "84:0B:7C:01:02:03",
                "serialNumber": "ABC123",
                "swVersion": "4.5.10.201-CD-UPC",
                "systemTime": "Fri Jun 17, 2022, 17:09:10",
                "systemUptime": "10 Days,17 Hours,33 Minutes,47 Seconds",
                "timezone": "1",
                "wanIp": "203.0.113.1/24",
            }
        ],
        "getCMInit": [
            {
                "bpiStatus": "AUTH:authorized, TEK:operational",
                "dhcp": "Success",
                "downloadCfg": "Success",
                "eaeStatus": "Secret",
                "findDownstream": "Success",
                "hwInit": "Success",
                "networkAccess": "Permitted",
                "ranging": "Success",
                "registration": "Success",
                "timeOfday": "Secret",
                "trafficStatus": "Enable",
            }
        ],
        "dsinfo": [
            {
                "channelId": "9",
                "frequency": "426250000",
                "modulation": "2",
                "portId": "1",
                "signalStrength": "17.400",
                "snr": "40.946",
            },
            {
                "channelId": "14",
                "frequency": "5030",
                "modulation": "9",
                "portId": "2",
                "signalStrength": "11.030",
                "snr": "13.243",
            },
        ],
        "usinfo": [
            {
                "bandwidth": "6400000",
                "channelId": "2",
                "frequency": "39400000",
                "portId": "1",
                "scdmaMode": "ATDMA",
                "signalStrength": "36.000",
            },
            {
                "bandwidth": "18",
                "channelId": "13",
                "frequency": "250",
                "portId": "2",
                "scdmaMode": "QFSP28",
                "signalStrength": "40.030",
            },
        ],
    }

    for name, payload in data.items():

        def make_data_handler(name, payload):
            """
            Binds name, payload to the values that they were when make_data_handler is
            called. "This happens because [name, payload are] not local to
            [data_handler], but [are] defined in the outer scope, and [they are]
            accessed when [data_handler] is called — not when it is defined." and "In
            order to avoid this, you need to save the values in variables local to
            [make_data_handler], so that they don’t rely on the value of the [variables
            within the outer scope]". Explanation adapted from:
            <https://docs.python.org/3/faq/programming.html#why-do-lambdas-defined-in-a-loop-with-different-values-all-return-the-same-result>
            """

            def data_handler(request: Request) -> Response:
                assert request.cookies.get("session") == "sessionid"
                return Response(json.dumps(payload), content_type="application/json")

            return data_handler

        httpserver.expect_request(
            f"/data/{name}.asp", method="GET"
        ).respond_with_handler(make_data_handler(name, payload))

    def logout_handler(request: Request) -> Response:
        assert request.cookies.get("session") == "sessionid"
        assert request.form.get("data") == "byebye"  # observed behaviour
        # Observed behaviour: preSession cookie is set to a different value in this
        # response; but to implement that, we'd have to make this into a stateful web
        # server.
        return Response(
            status=302,
            headers={
                "Location": httpserver.url_for("/login.html"),
            },
        )

    httpserver.expect_request("/goform/logout", method="POST").respond_with_handler(
        logout_handler
    )

    return httpserver


def test_probe(container, hitron_cert, hitron_server):
    # given:
    cert_der = ssl.PEM_cert_to_DER_cert(
        hitron_cert.cert_chain_pems[0].bytes().decode("ascii")
    )
    digest = hashlib.sha256(cert_der).digest()
    fingerprint = binascii.hexlify(digest, ":").decode("ascii")

    http = urllib3.PoolManager(retries=False)
    url = f"http://{container[0]}:{container[1]}/probe"

    # when:
    r = http.request(
        "GET",
        url,
        fields={
            "target": "10.0.2.2",
            "fingerprint": fingerprint,
            "_port": str(hitron_server.port),
            "usr": "uuu",
            "pwd": "ppp",
        },
    )
    # breakpoint()

    # then:
    hitron_server.check()
    assert r.status == 200
