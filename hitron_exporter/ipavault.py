from typing import Sequence

from ipalib import api


api_finalized = False


def retrieve(vault_namespace):
    maybe_finalize_api()

    api.Backend.rpcclient.connect()
    try:
        return {
            'usr': _retrieve(vault_namespace, 'usr'),
            'pwd': _retrieve(vault_namespace, 'pwd'),
        }
    finally:
        api.Backend.rpcclient.disconnect()


def maybe_finalize_api():
    global api_finalized
    if not api_finalized:
        api.bootstrap(context='cli')
        api.finalize()
        api_finalized = True


def _retrieve(vault_namespace: Sequence[str], vault_name):
    if vault_namespace == 'shared':
        kwargs = {'shared': True}
    elif vault_namespace[0] == 'user':
        kwargs = {'user': vault_namespace[1]}
    elif vault_namespace[0] == 'service':
        kwargs = {'service': vault_namespace[1]}
    else:
        raise ValueError('vault_namespace[0] should be one of shared/username/service')

    return api.Command.vault_retrieve(vault_name, **kwargs)['result']['data'].decode('ascii')
