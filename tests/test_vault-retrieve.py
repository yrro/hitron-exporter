from __future__ import print_function

import builtins
import io
from importlib import resources
import json
from pprint import pprint
from unittest.mock import Mock


def test_vault_retrieve(capsys, monkeypatch):
    # given
    ipa_api = Mock()

    def mock_vault_retrieve(name, /, service=None):
        assert service == "HTTP/cm-hitron.example.com"
        match name:
            case "usr":
                return {
                    "result": {"data": b"uuu"},
                    "summary": "blah",
                    "value": name,
                }
            case "pwd":
                return {
                    "result": {"data": b"ppp"},
                    "summary": "blah",
                    "value": name,
                }
            case _:
                raise AssertionError("vault not found")

    ipa_api.Command.vault_retrieve.side_effect = mock_vault_retrieve

    local = {
        "api": ipa_api,
        "pp": pprint,
        "__builtins__": builtins,
    }

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

    # when
    #
    # <https://github.com/freeipa/freeipa/blob/074c2f5421b6d8f634746027816785f023a91d51/ipalib/cli.py#L1014>
    # ... ipalib passes globals() in, but when we do that, the script throws
    # NameError("name 'api' is not defined"). I don't understand why, but we
    # can work around that by passing in an explicit global variable mapping.
    exec(compiled, {"api": ipa_api}, local)  # pylint: disable=exec-used

    # then
    cap = capsys.readouterr()
    out_json = json.loads(cap.out)
    assert out_json == {"usr": "uuu", "pwd": "ppp"}
