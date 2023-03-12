import pytest
from unittest import mock

import prometheus_client

import hitron_exporter.flask_app
import hitron_exporter.hitron
import hitron_exporter.prometheus


@pytest.fixture
def mock_client():
    return mock.create_autospec(hitron_exporter.hitron.Client)


@pytest.fixture
def mock_registry():
    return mock.create_autospec(prometheus_client.CollectorRegistry)


@pytest.fixture
def mock_collector():
    return mock.create_autospec(hitron_exporter.prometheus.Collector)


@pytest.fixture(autouse=True)
def mock_app_integrations(monkeypatch, mock_client, mock_registry, mock_collector):
    monkeypatch.setattr("hitron_exporter.hitron.Client", mock_client)

    def mock_vault_retrieve(container):
        assert container[0] == "service"
        assert container[1] == "sv"
        return {"usr": "U", "pwd": "P"}

    monkeypatch.setattr("hitron_exporter.ipavault.retrieve", mock_vault_retrieve)

    monkeypatch.setattr("prometheus_client.CollectorRegistry", mock_registry)
    monkeypatch.setattr("hitron_exporter.prometheus.Collector", mock_collector)

    return hitron_exporter.flask_app.create_app()


@pytest.fixture
def flask_client(mock_app_integrations):
    return mock_app_integrations.test_client()


def test_metrics(flask_client):
    res = flask_client.get("/metrics")
    assert res.status.startswith("200 ")


def test_no_params(flask_client):
    res = flask_client.get("/probe")
    assert res.status.startswith("400 ") and "Missing" in res.text


def test_no_fingerprint(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "u", "pwd": "p"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("u", "p", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_fingerprint(flask_client, mock_client):
    res = flask_client.get(
        "/probe",
        query_string={"target": "tt", "fingerprint": "fpr", "usr": "u", "pwd": "p"},
    )
    mock_client.assert_called_with("tt", fingerprint="fpr")
    mock_client.return_value.login.assert_called_with("u", "p", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


def test_without_force(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "u", "pwd": "p"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("u", "p", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_force0(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "force": "0", "usr": "u", "pwd": "p"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("u", "p", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_force1(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "force": "1", "usr": "u", "pwd": "p"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("u", "p", force=True)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_usr(flask_client):
    res = flask_client.get("/probe", query_string={"target": "tt", "usr": "uu"})
    assert res.status.startswith("400 ") and "Missing" in res.text


def test_with_pwd(flask_client):
    res = flask_client.get("/probe", query_string={"target": "tt", "pwd": "pp"})
    assert res.status.startswith("400 ") and "Missing" in res.text


def test_with_usr_pwd(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "uu", "pwd": "pp"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("uu", "pp", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")


@pytest.mark.xfail(reason="Can't get mocking to work as expected")
def test_collection(flask_client, mock_client, mock_collector, mock_registry):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "uu", "pwd": "pp"}
    )
    mock_collector.collect.assert_called()
    assert res.status.startswith("200 ")


def test_with_vault(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "ipa_vault_namespace": "service:sv"}
    )
    mock_client.assert_called_with("tt", fingerprint=None)
    mock_client.return_value.login.assert_called_with("U", "P", force=False)
    mock_client.return_value.logout.assert_called()
    assert res.status.startswith("200 ")
