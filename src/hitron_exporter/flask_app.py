from typing import Optional, TypedDict

import flask
import prometheus_client
from flask.typing import ResponseReturnValue

from . import hitron  # noqa: E402
from . import ipavault  # noqa: E402
from . import prometheus

AppGlobals = TypedDict(
    "AppGlobals", {"ipavault_credentials": Optional[ipavault.Credential]}
)
globals_: AppGlobals = {"ipavault_credentials": None}


def create_app() -> flask.Flask:
    app = flask.Flask(__name__)
    prometheus.metrics.init_app(app)
    app.add_url_rule("/probe", view_func=probe)
    return app


def probe() -> ResponseReturnValue:
    args = flask.request.args

    if not (target := args.get("target")):
        return "Missing parameter: 'target'", 400
    kwargs = {}
    if port := args.get("_port"):
        kwargs["port"] = int(port)
    client = hitron.Client(target, args.get("fingerprint"), **kwargs)

    force = bool(int(args.get("force", "0")))

    if args.get("usr") and args.get("pwd"):
        client.login(args["usr"], args["pwd"], force)
    elif args.get("ipa_vault_namespace"):
        creds = globals_["ipavault_credentials"]
        if creds is None:
            creds = ipavault.retrieve(args["ipa_vault_namespace"].split(":"))

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
        reg = prometheus_client.CollectorRegistry()
        reg.register(prometheus.Collector(client))
        return prometheus_client.make_wsgi_app(reg)
    finally:
        client.logout()
