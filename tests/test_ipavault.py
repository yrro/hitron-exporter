import json
from unittest import mock

from hitron_exporter import ipavault


def test_retrieve_ok(monkeypatch):
    # given:
    expected = json.dumps({"a": 1, "b": 2})
    mock_completed = mock.Mock()
    mock_completed.stdout = json.dumps(expected)
    mock_run = mock.Mock(return_value=mock_completed)
    monkeypatch.setattr("subprocess.run", mock_run)

    # when:
    data = ipavault.retrieve(["service", "HTTP/blah.example.com"])

    # then:
    assert data == expected


def test_keytab_unreadable(tmp_path, monkeypatch, caplog):
    # given:
    keytab_path = tmp_path / "krb5.keytab"
    keytab_path.touch(mode=0)
    monkeypatch.setenv("KRB5_CLIENT_KTNAME", str(keytab_path))

    # when:
    ipavault._check_keytab_readable()

    # then
    expected_messages = (
        rec
        for rec in caplog.records
        if rec.name.startswith("hitron_exporter.")
        and "is not readable; we" in rec.message
    )
    assert any(expected_messages)
