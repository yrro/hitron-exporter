from importlib import resources
import json
from logging import getLogger
import os
import subprocess
from typing import Sequence, TypedDict


Credential = TypedDict("Credential", {"usr": str, "pwd": str})

LOGGER = getLogger(__name__)


def retrieve(vault_namespace: Sequence[str]) -> Credential:
    check_keytab_readable()

    kwargs: dict[str, str] = {}
    if vault_namespace[0] in ["user", "service"]:
        kwargs[vault_namespace[0]] = vault_namespace[1]
    else:
        raise ValueError("vault_namespace[0] must be 'user' or 'service'")

    source = resources.files("hitron_exporter").joinpath("vault-retrieve.py")
    with resources.as_file(source) as vault_retrieve_py:
        input_ = json.dumps(kwargs)
        LOGGER.debug("Launching vault-retrieve.py with input: %r", input)
        proc = subprocess.run(
            ["ipa", "console", str(vault_retrieve_py)],
            input=input_,
            stdout=subprocess.PIPE,
            check=True,
        )
        LOGGER.debug("... output: %r", proc.stdout)

    cred: Credential = json.loads(proc.stdout)
    return cred


def check_keytab_readable() -> None:
    if "KRB5_CLIENT_KTNAME" not in os.environ:
        return

    # MIT Kerberos doesn't log any errors if the keytab isn't accessible. This
    # check isn't perfect, because it won't catch the case where the client
    # keytab is in the default location & this environment variable is unset.
    try:
        # pylint: disable=unspecified-encoding
        with open(os.environ["KRB5_CLIENT_KTNAME"]) as _:
            pass
    except Exception:  # pylint: disable=broad-exception-caught
        LOGGER.exception(
            (
                "The keytab %r is not readable; we will not be able to retrieve"
                " credentials from FreeIPA"
            ),
            os.environ["KRB5_CLIENT_KTNAME"],
        )
