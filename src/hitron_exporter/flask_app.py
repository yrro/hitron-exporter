from typing import Optional, TypedDict

import flask
import prometheus_client
from dependency_injector import containers, providers
from flask.typing import ResponseReturnValue

from . import hitron  # noqa: E402
from . import ipavault  # noqa: E402
from . import prometheus

AppGlobals = TypedDict(
    "AppGlobals", {"ipavault_credentials": Optional[ipavault.Credential]}
)
globals_: AppGlobals = {"ipavault_credentials": None}


class Container(
    containers.DeclarativeContainer
):  # pylint: disable=too-few-public-methods
    client_factory = providers.Factory(hitron.Client)
    make_wsgi_app = providers.Callable(prometheus_client.make_wsgi_app)
    registry_factory = providers.Factory(prometheus_client.CollectorRegistry)
    collector_factory = providers.Factory(prometheus.Collector)
    vault_retrieve = providers.Callable(ipavault.retrieve)

    @staticmethod
    def get() -> "Container":  # typing.Self in Python 3.11
        return flask.current_app.container  # type: ignore [attr-defined, no-any-return]


def create_app() -> flask.Flask:
    container = Container()
    container.check_dependencies()  # pylint: disable=no-member
    app = flask.Flask("hitron_exporter")
    app.container = container  # type: ignore [attr-defined]
    prometheus.metrics.init_app(app)
    app.add_url_rule("/probe", view_func=probe)
    return app


def probe() -> ResponseReturnValue:
    args = flask.request.args

    if not (target := args.get("target")):
        return "Missing parameter: 'target'", 400
    client_kwargs = {}
    if port := args.get("_port"):
        client_kwargs["port"] = int(port)
    client = Container.get().client_factory(
        target, args.get("fingerprint"), **client_kwargs
    )

    force = bool(int(args.get("force", "0")))

    if args.get("usr") and args.get("pwd"):
        client.login(args["usr"], args["pwd"], force)
    elif args.get("ipa_vault_namespace"):
        creds = globals_["ipavault_credentials"]
        if creds is None:
            creds = Container.get().vault_retrieve(
                args["ipa_vault_namespace"].split(":")
            )

        if creds is not None:
            try:
                client.login(**creds, force=force)
            except PermissionError:
                creds = None
                raise
            finally:
                globals_["ipavault_credentials"] = creds
    else:
        return "Missing parameters: 'usr', 'pwd' or 'ipa_vault_namespace'", 400

    try:
        col = Container.get().collector_factory(client)
    finally:
        client.logout()

    reg = Container.get().registry_factory()
    reg.register(col)
    wsgi_app: ResponseReturnValue = Container.get().make_wsgi_app(reg)
    return wsgi_app
