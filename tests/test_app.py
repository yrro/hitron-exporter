import pytest
from unittest import mock

import prometheus_client
from dependency_injector import providers

import hitron_exporter.flask_app
import hitron_exporter.hitron
import hitron_exporter.prometheus


@pytest.fixture
def mock_client():
    return mock.create_autospec(hitron_exporter.hitron.Client, instance=True)


@pytest.fixture
def mock_registry():
    return mock.create_autospec(prometheus_client.CollectorRegistry, instance=True)


@pytest.fixture
def mock_collector():
    return mock.create_autospec(hitron_exporter.prometheus.Collector, instance=True)


@pytest.fixture
def app(mock_client, mock_registry, mock_collector):
    def mock_vault_retrieve(container):
        assert container[0] == "service"
        assert container[1] == "sv"
        return {"usr": "U", "pwd": "P"}

    app = hitron_exporter.flask_app.create_app()
    app.container.client_factory.override(mock_client)
    app.container.collector_factory.override(mock_collector)
    app.container.registry_factory.override(mock_registry)
    app.container.vault_retrieve.override(providers.Callable(mock_vault_retrieve))
    app.config.update({"TESTING": True})
    return app


@pytest.fixture
def flask_client(app):
    return app.test_client()


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
    # mock_Client.return_value.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("u", "p", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_fingerprint(flask_client, mock_client):
    res = flask_client.get(
        "/probe",
        query_string={"target": "tt", "fingerprint": "fpr", "usr": "u", "pwd": "p"},
    )
    # mock_Client.assert_called_with("tt", fingerprint="fpr")
    mock_client.login.assert_called_with("u", "p", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")


def test_without_force(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "u", "pwd": "p"}
    )
    # mock_Client.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("u", "p", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_force0(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "force": "0", "usr": "u", "pwd": "p"}
    )
    # mock_Client.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("u", "p", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")


def test_with_force1(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "force": "1", "usr": "u", "pwd": "p"}
    )
    # mock_Client.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("u", "p", force=True)
    mock_client.logout.assert_called()
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
    # mock_Client.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("uu", "pp", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")


def test_collection(flask_client, mock_client, mock_collector, mock_registry):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "usr": "uu", "pwd": "pp"}
    )
    # mock_collector.assert_called_with(mock_client)
    mock_client.login.assert_called_with("uu", "pp", force=False)
    mock_client.logout.assert_called()
    mock_registry.register.assert_called_with(mock_collector)
    assert res.status.startswith("200 ")


def test_with_vault(flask_client, mock_client):
    res = flask_client.get(
        "/probe", query_string={"target": "tt", "ipa_vault_namespace": "service:sv"}
    )
    # mock_Client.assert_called_with("tt", fingerprint=None)
    mock_client.login.assert_called_with("U", "P", force=False)
    mock_client.logout.assert_called()
    assert res.status.startswith("200 ")
