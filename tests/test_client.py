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
    # CN=02:00:00:00:00:00,OU=No. 40\, Wu-kung 5th Rd.\, Wu-ku\, Taipei Hsien\, Taiwan,O=Hitron Technologies,C=TW
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

    # then
    with pytest.raises(
        urllib3.exceptions.SSLError, match="Fingerprints did not match."
    ):
        # when
        client.http_request("GET", httpserver.url_for("/"), retries=False)


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

    # when:
    client.http_request("GET", httpserver.url_for("/"), retries=False)

    # then:
    print(f"expected fingerprint: {fingerprint}")
    assert any(
        (
            (logger, level, message)
            for (logger, level, message) in caplog.record_tuples
            if logger.startswith("hitron_exporter.") and fingerprint in message
        )
    )


def test_login_logout(httpserver) -> None:
    # given:
    httpserver.expect_ordered_request("/", method="GET").respond_with_data(
        "", status=302, headers={"Set-Cookie": "preSession=presession_id; path=/"}
    )

    def login_handler(request: Request) -> Response:
        assert request.form["usr"] == "uuu"
        assert request.form["pwd"] == "ppp"
        assert request.form["preSession"] == "presession_id"
        return Response(
            "success", headers={"Set-Cookie": "session=sessionid; path=/; HttpOnly"}
        )

    httpserver.expect_ordered_request(
        "/goform/login", method="POST"
    ).respond_with_handler(login_handler)

    def logout_handler(request: Request) -> Response:
        assert request.cookies["session"] == "sessionid"
        assert request.form["data"] == "byebye"  # observed behaviour
        return Response(status=302)

    httpserver.expect_ordered_request(
        "/goform/logout", method="POST"
    ).respond_with_handler(logout_handler)

    client = Client("localhost", fingerprint="", port=httpserver.port)

    try:
        # when:
        client.login("uuu", "ppp")
        client.logout()
    finally:
        # then:
        httpserver.check()


def test_get_data(httpserver) -> None:
    # given:
    httpserver.expect_request("/data/getTuneFreq.asp", method="GET").respond_with_json(
        [{"tunefreq": "213.45"}]
    )

    client = Client("localhost", fingerprint="", port=httpserver.port)

    # when:
    data = client.get_data(Client.Dataset.TUNEFREQ)

    # then:
    data == [{"tunefreq": "213.45"}]
