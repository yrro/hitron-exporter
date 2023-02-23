import datetime
from importlib import metadata
from logging import getLogger
import re
from typing import Iterator, Optional

import flask
from prometheus_flask_exporter import PrometheusMetrics  # type: ignore [import]
from flask.typing import ResponseReturnValue
import prometheus_client
from prometheus_client.core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    InfoMetricFamily,
)
from typing_extensions import TypedDict

from . import log_config

log_config.config_early()

from . import hitron  # noqa: E402
from . import ipavault  # noqa: E402


AppGlobals = TypedDict(
    "AppGlobals", {"ipavault_credentials": Optional[ipavault.Credential]}
)
globals_: AppGlobals = {"ipavault_credentials": None}


LOGGER = getLogger(__name__)

app = flask.Flask(__name__)
metrics = PrometheusMetrics(app, path=None)

prometheus_client_app = prometheus_client.make_wsgi_app()


@app.before_first_request
def info_metric() -> None:
    metrics.info(
        "hitron_exporter_info",
        "Information about hitron-exporter itself",
        version=metadata.version("hitron-exporter"),
    )


@app.route("/metrics")
def metrics_() -> ResponseReturnValue:
    """
    For some reason the PromtheusMetrics route shows up when running '/metrics', but
    calling it results in a 404 error. So we'll continue to manually wire
    a route to the prometheus_client's provided WSGI app.
    """
    return prometheus_client_app


@app.route("/probe")
def probe() -> ResponseReturnValue:
    args = flask.request.args

    try:
        target = args["target"]
    except KeyError:
        return "Missing parameter: 'target'", 400
    client = hitron.Client(target, args.get("fingerprint"))

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
        reg.register(Collector(client))
        return prometheus_client.make_wsgi_app(reg)
    finally:
        client.logout()


class Collector(prometheus_client.registry.Collector):
    def __init__(self, client: hitron.Client) -> None:
        self.__dsinfo = client.get_data(client.Dataset.DSINFO)
        self.__usinfo = client.get_data(client.Dataset.USINFO)
        self.__sysinfo = client.get_data(client.Dataset.SYSINFO)
        self.__system_model = client.get_data(client.Dataset.SYSTEM_MODEL)
        self.__cminit = client.get_data(client.Dataset.CMINIT)

    def collect(self) -> Iterator[prometheus_client.Metric]:
        yield from self.collect_usinfo()
        yield from self.collect_dsinfo()
        yield from self.collect_uptime()
        yield from self.collect_network()
        yield from self.collect_sysinfo()
        yield from self.collect_docsis()

    def collect_usinfo(self) -> Iterator[GaugeMetricFamily]:
        usinfo_sigstr = GaugeMetricFamily(
            "hitron_channel_upstream_signal_strength_dbmv",
            "",
            labels=["port", "channel", "frequency"],
        )
        usinfo_bw = GaugeMetricFamily(
            "hitron_channel_upstream_bandwidth",
            "",
            labels=["port", "channel", "frequency"],
        )

        for uschannel in self.__usinfo:
            key = [uschannel["portId"], uschannel["channelId"], uschannel["frequency"]]
            usinfo_sigstr.add_metric(key, float(uschannel["signalStrength"]))
            usinfo_bw.add_metric(key, int(uschannel["bandwidth"]))

        yield usinfo_sigstr
        yield usinfo_bw

    def collect_dsinfo(self) -> Iterator[GaugeMetricFamily]:
        dsinfo_sigstr = GaugeMetricFamily(
            "hitron_channel_downstream_signal_strength_dbmv",
            "",
            labels=["port", "channel", "frequency"],
        )
        dsinfo_snr = GaugeMetricFamily(
            "hitron_channel_downstream_snr", "", labels=["port", "channel", "frequency"]
        )

        for dschannel in self.__dsinfo:
            key = [dschannel["portId"], dschannel["channelId"], dschannel["frequency"]]
            dsinfo_sigstr.add_metric(key, float(dschannel["signalStrength"]))
            dsinfo_snr.add_metric(key, float(dschannel["snr"]))

        yield dsinfo_sigstr
        yield dsinfo_snr

    def collect_uptime(self) -> Iterator[CounterMetricFamily]:
        m = re.match(
            r"(\d+) Days,(\d+) Hours,(\d+) Minutes,(\d+) Seconds",
            self.__sysinfo[0]["systemUptime"],
        )
        if m:
            td = datetime.timedelta(
                days=int(m.group(1)),
                hours=int(m.group(2)),
                minutes=int(m.group(3)),
                seconds=int(m.group(4)),
            )
            yield CounterMetricFamily(
                "hitron_system_uptime_seconds_total", "", value=td.total_seconds()
            )

    def collect_network(self) -> Iterator[CounterMetricFamily]:
        nw_tx = CounterMetricFamily(
            "hitron_network_transmit_bytes", "", labels=["device"]
        )

        nbytes = self.parse_pkt(self.__sysinfo[0]["LSendPkt"])
        if nbytes:
            nw_tx.add_metric(["lan"], nbytes)

        nbytes = self.parse_pkt(self.__sysinfo[0]["WSendPkt"])
        if nbytes:
            nw_tx.add_metric(["wan"], nbytes)

        yield nw_tx

        nw_rx = CounterMetricFamily(
            "hitron_network_receive_bytes", "", labels=["device"]
        )

        nbytes = self.parse_pkt(self.__sysinfo[0]["LRecPkt"])
        if nbytes:
            nw_rx.add_metric(["lan"], nbytes)

        nbytes = self.parse_pkt(self.__sysinfo[0]["WRecPkt"])
        if nbytes:
            nw_rx.add_metric(["wan"], nbytes)

        yield nw_rx

    def parse_pkt(self, pkt: str) -> Optional[float]:
        m = re.match(r"(\d+(?:\.\d+)?)([A-Z]?) Bytes", pkt)
        if not m:
            LOGGER.error("Couldn't parse %r as pkt", pkt)
            return None

        factor = {
            "": 1,
            "K": 1e3,
            "M": 1e6,
            "G": 1e9,
        }.get(m.group(2))
        if not factor:
            LOGGER.error("Unknown pkt factor %r", m.group(2))
            return None

        return float(m.group(1)) * factor

    def collect_sysinfo(self) -> Iterator[InfoMetricFamily]:
        yield InfoMetricFamily(
            "hitron_system",
            "",
            value={
                "serial_number": self.__sysinfo[0]["serialNumber"],
                "software_version": self.__sysinfo[0]["swVersion"],
                "hardware_version": self.__sysinfo[0]["hwVersion"],
                "model_name": self.__system_model["modelName"],
            },
        )

    def collect_docsis(self) -> Iterator[InfoMetricFamily]:
        bpi = {}
        for element in self.__cminit[0]["bpiStatus"].split(","):
            k, _, v = element.strip().partition(":")
            bpi[k.lower()] = v.lower()
        yield InfoMetricFamily(
            "hitron_cm_bpi", "Cable Modem Baseline Privacy Interface", value=bpi
        )
