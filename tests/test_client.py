import binascii
import hashlib
import ssl

import pytest
import trustme
import urllib3.exceptions
from werkzeug.wrappers import Request, Response

from hitron_exporter.hitron import Client


@pytest.fixture(scope="session")
def ca():
    return trustme.CA()


@pytest.fixture(scope="session")
def localhost_cert(ca):
    # The real web server's TLS server certificate has no Subject Alternative Name
    # values, and a subject of:
    # CN=02:00:00:00:00:00,
    # OU=No. 40\, Wu-kung 5th Rd.\, Wu-ku\, Taipei Hsien\, Taiwan,
    # O=Hitron Technologies,
    # C=TW
    return ca.issue_cert(common_name="02:00:00:00:00:00")


@pytest.fixture(scope="session")
def httpserver_ssl_context(localhost_cert):
    """
    This fixture causes pytest_httpserver to become an HTTPS server.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cert.configure_cert(context)
    return context


def test_fingerprint_checked(httpserver, localhost_cert) -> None:
    # given:
    client = Client(
        "localhost",
        fingerprint="00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        port=httpserver.port,
    )

    # then:
    with pytest.raises(
        urllib3.exceptions.SSLError, match="Fingerprints did not match."
    ):
        # when
        client.http_request("GET", httpserver.url_for("/"))

    # then:
    httpserver.check()


@pytest.mark.filterwarnings("ignore::urllib3.connectionpool.InsecureRequestWarning")
def test_fingerprint_optional(httpserver, localhost_cert, caplog) -> None:
    # given:
    client = Client(
        "localhost",
        fingerprint=None,
        port=httpserver.port,
    )
    cert_der = ssl.PEM_cert_to_DER_cert(
        localhost_cert.cert_chain_pems[0].bytes().decode("ascii")
    )
    digest = hashlib.sha256(cert_der).digest()
    fingerprint = binascii.hexlify(digest, ":").decode("ascii")

    httpserver.expect_request("/", method="GET").respond_with_data("")

    # when:
    client.http_request("GET", httpserver.url_for("/"))

    # then:
    httpserver.check()
    expected_messages = (
        rec
        for rec in caplog.records
        if rec.name.startswith("hitron_exporter.") and fingerprint in rec.message
    )
    assert any(expected_messages)


def test_login_logout(httpserver) -> None:
    # given:
    httpserver.expect_request("/", method="GET").respond_with_data(
        "", status=302, headers={"Set-Cookie": "preSession=presession_id; path=/"}
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

    logout_called = {}

    def logout_handler(request: Request) -> Response:
        assert request.cookies.get("session") == "sessionid"
        assert request.form.get("data") == "byebye"  # observed behaviour
        logout_called["called"] = True
        return Response(
            status=302,
            headers={
                "Set-Cookie": (
                    "session=deleted; path=/; HttpOnly; expires=Thu, 01 Jan 1970"
                    " 00:00:00 GMT"
                )
            },
        )

    httpserver.expect_request("/goform/logout", method="POST").respond_with_handler(
        logout_handler
    )

    client = Client("localhost", fingerprint="", port=httpserver.port)

    # when:
    client.login("uuu", "ppp")
    client.logout()

    # then:
    httpserver.check()
    assert logout_called.get("called")


def test_cookies_not_divulged_to_second_host(httpserver) -> None:
    # given:
    httpserver.expect_request("/", method="GET").respond_with_data(
        "",
        headers={
            "Set-Cookie": "for-localhost=1; path=/",
        },
    )

    def handler2(request: Request) -> Response:
        assert request.headers.get("Host") == f"host2.localhost:{httpserver.port}"
        assert "Cookie" not in request.headers

    httpserver.expect_request("/handler2", method="GET").respond_with_handler(handler2)

    client = Client("localhost", fingerprint="", port=httpserver.port)
    r1 = client.http_request("GET", httpserver.url_for("/"))
    assert r1.status == 200

    # when:
    r2 = client.http_request(
        "GET", f"https://host2.localhost:{httpserver.port}/handler2"
    )

    # then:
    httpserver.check()
    assert r2.status == 200


def test_get_data(httpserver) -> None:
    # given:
    httpserver.expect_request("/data/getTuneFreq.asp", method="GET").respond_with_json(
        [{"tunefreq": "213.45"}]
    )

    client = Client("localhost", fingerprint="", port=httpserver.port)

    # when:
    data = client.get_data(Client.Dataset.TUNEFREQ)

    # then:
    httpserver.check()
    assert data == [{"tunefreq": "213.45"}]
