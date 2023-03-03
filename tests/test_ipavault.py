import subprocess
from unittest.mock import MagicMock, Mock

from hitron_exporter import ipavault


def test_retrieve_ok(monkeypatch):
    # given:
    mock_completed = Mock(spec_set=subprocess.CompletedProcess)
    expected = {"a": 1, "b": 2}
    mock_popen = MagicMock(spec_set=subprocess.Popen)
    mock_popen.return_value.__enter__.return_value = mock_completed
    monkeypatch.setattr("subprocess.Popen", mock_popen)

    # when:
    data = ipavault.retrieve(["service", "HTTP/blah.example.com"])

    # then:
    assert data == expected_data
