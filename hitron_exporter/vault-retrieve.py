import json
import sys
from typing import Any

api: Any  # injected by ipa console command


def retrieve(name: str, **kwargs_: Any) -> str:
    # pylint: disable=undefined-variable
    result = api.Command.vault_retrieve(name, **kwargs_)  # noqa: F821
    data: bytes = result["result"]["data"]
    return data.decode("utf-8")


kwargs = json.load(sys.stdin)

output = {
    "usr": retrieve("usr", **kwargs),
    "pwd": retrieve("pwd", **kwargs),
}

json.dump(output, sys.stdout)
