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
