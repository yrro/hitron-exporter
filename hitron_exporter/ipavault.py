from logging import getLogger
import os
from typing import Sequence


LOGGER = getLogger(__name__)


api_finalized = False


def retrieve(vault_namespace):
    check_keytab_readable()

    maybe_finalize_api()

    api.Backend.rpcclient.connect()
    try:
        return {
            "usr": _retrieve(vault_namespace, "usr"),
            "pwd": _retrieve(vault_namespace, "pwd"),
        }
    finally:
        api.Backend.rpcclient.disconnect()


def check_keytab_readable():
    if "KRB5_CLIENT_KTNAME" not in os.environ:
        return

    # MIT Kerberos doesn't log any errors if the keytab isn't accessible. This
    # check isn't perfect, because it won't catch the case where the client
    # keytab is in the default location & this environment variable is unset.
    try:
        with open(os.environ["KRB5_CLIENT_KTNAME"]) as _:
            pass
    except Exception:
        LOGGER.exception(
            (
                "The client keytab %r is not readable; we will not be able to retrieve"
                " credentials from FreeIPA"
            ),
            os.environ["KRB5_CLIENT_KTNAME"],
        )


def maybe_finalize_api():
    # Import ipalib lazily here, since it is an optional dependency
    global api
    from ipalib import api

    global api_finalized
    if not api_finalized:
        api.bootstrap(context="cli")
        api.finalize()
        api_finalized = True


def _retrieve(vault_namespace: Sequence[str], vault_name):
    if vault_namespace == "shared":
        kwargs = {"shared": True}
    elif vault_namespace[0] == "user":
        kwargs = {"user": vault_namespace[1]}
    elif vault_namespace[0] == "service":
        kwargs = {"service": vault_namespace[1]}
    else:
        raise ValueError("vault_namespace[0] should be one of shared/username/service")

    return api.Command.vault_retrieve(vault_name, **kwargs)["result"]["data"].decode(
        "ascii"
    )
