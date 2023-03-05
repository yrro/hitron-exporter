from __future__ import print_function

import io
from importlib import resources
import json
from unittest import mock

import pytest

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


def test_vault_retrieve(capsys, monkeypatch):
    # given
    ipa_api = mock.Mock(spec_set=["Command"])
    ipa_api.Command = mock.Mock(spec_set=["vault_retrieve"])

    def mock_vault_retrieve(name, /, service=None):
        assert service == "HTTP/cm-hitron.example.com"
        if name == "usr":
            return {
                "result": {"data": b"uuu"},
                "summary": "blah",
                "value": name,
            }
        elif name == "pwd":
            return {
                "result": {"data": b"ppp"},
                "summary": "blah",
                "value": name,
            }
        else:
            pytest.fail(f"unknown vault {name!r}")

    ipa_api.Command.vault_retrieve.side_effect = mock_vault_retrieve

    script = resources.files("hitron_exporter").joinpath("vault-retrieve.py")
    with resources.as_file(script) as source_path:
        with open(source_path, "r", encoding="utf-8") as source_code:
            compiled = compile(
                source_code.read(),
                source_path,
                "exec",
                flags=print_function.compiler_flag,
            )

    monkeypatch.setattr(
        "sys.stdin", io.StringIO('{"service": "HTTP/cm-hitron.example.com"}')
    )

    # <https://github.com/freeipa/freeipa/blob/074c2f5421b6d8f634746027816785f023a91d51/ipalib/cli.py#L1014>
    # ipalib passes globals() in, but when we do that, the script throws NameError("name
    # 'api' is not defined"). I don't understand why, but we can work around that by
    # passing in an explicit global variable mapping instead.
    exec(compiled, {"api": ipa_api})  # pylint: disable=exec-used

    # then
    cap = capsys.readouterr()
    out_json = json.loads(cap.out)
    assert out_json == {"usr": "uuu", "pwd": "ppp"}


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
