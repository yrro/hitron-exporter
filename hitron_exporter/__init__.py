import re

import flask
import prometheus_client
import prometheus_client.core

from . import hitron
from . import ipavault


ipavault_credentials = None
app = flask.Flask(__name__)

prometheus_client_app = prometheus_client.make_wsgi_app()


@app.route("/metrics")
def metrics():
    return prometheus_client_app


@app.route("/probe")
def probe():
    global ipavault_credentials
    args = flask.request.args

    try:
        address = args['address']
    except KeyError:
        return "Missing parameter: 'address'", 400
    client = hitron.Client(address, args.get('fingerprint'))

    force = bool(int(args.get('force', '0')))

    if args.get('usr') and args.get('pwd'):
        client.login(args.get('usr'), args.get('pwd'), force)
    elif args.get('ipa_vault_namespace'):
        if ipavault_credentials is None:
            ipavault_credentials = ipavault.retrieve(args.get('ipa_vault_namespace').split(':'))
        try:
            client.login(**ipavault_credentials, force=force)
        except PermissionError:
            ipavault_credentials = None
            raise
    else:
        return "Missing parameters: 'usr', 'pwd' or 'ipa_vault_namespace'", 400

    try:
        reg = prometheus_client.CollectorRegistry()
        reg.register(Collector(client))
        return prometheus_client.make_wsgi_app(reg)
    finally:
        client.logout()


class Collector:
    def __init__(self, client):
        self.__dsinfo = client.get_data(client.DATASET_DSINFO)
        self.__usinfo = client.get_data(client.DATASET_USINFO)
        self.__sysinfo = client.get_data(client.DATASET_SYSINFO)
        self.__system_model = client.get_data(client.DATASET_SYSTEM_MODEL)
        self.__cminit = client.get_data(client.DATASET_CMINIT)

    def collect(self):
        yield from self.collect_usinfo()
        yield from self.collect_dsinfo()
        yield from self.collect_uptime()
        yield from self.collect_network()
        yield from self.collect_sysinfo()
        yield from self.collect_docsis()

    def collect_usinfo(self):
        usinfo_sigstr = prometheus_client.core.GaugeMetricFamily('hitron_channel_upstream_signal_strength_dbmv', '', labels=['port', 'channel', 'frequency'])
        usinfo_bw = prometheus_client.core.GaugeMetricFamily('hitron_channel_upstream_bandwidth', '', labels=['port', 'channel', 'frequency'])

        for uschannel in self.__usinfo:
            key = [uschannel['portId'], uschannel['channelId'], uschannel['frequency']]
            usinfo_sigstr.add_metric(key, float(uschannel['signalStrength']))
            usinfo_bw.add_metric(key, int(uschannel['bandwidth']))

        yield usinfo_sigstr
        yield usinfo_bw


    def collect_dsinfo(self):
        dsinfo_sigstr = prometheus_client.core.GaugeMetricFamily('hitron_channel_downstream_signal_strength_dbmv', '', labels=['port', 'channel', 'frequency'])
        dsinfo_snr = prometheus_client.core.GaugeMetricFamily('hitron_channel_downstream_snr', '', labels=['port', 'channel', 'frequency'])

        for dschannel in self.__dsinfo:
            key = [dschannel['portId'], dschannel['channelId'], dschannel['frequency']]
            dsinfo_sigstr.add_metric(key, float(dschannel['signalStrength']))
            dsinfo_snr.add_metric(key, float(dschannel['snr']))

        yield dsinfo_sigstr
        yield dsinfo_snr

    
    def collect_uptime(self):
        uptime = prometheus_client.core.CounterMetricFamily('hitron_system_uptime_seconds_total', '')

        m = re.match(r'(\d+) Days,(\d+) Hours,(\d+) Minutes,(\d+) Seconds', self.__sysinfo[0]['systemUptime'])
        if m:
            uptime.add_metric([], 86400 * int(m.group(1)) + 3660 * int(m.group(2)) + int(m.group(3)))

        yield uptime


    def collect_network(self):
        nw_tx = prometheus_client.core.CounterMetricFamily('hitron_network_transmit_bytes', '', labels=['device'])

        m = re.match(r'(\d+(?:\.\d+)?)M Bytes', self.__sysinfo[0]['LSendPkt'])
        if m:
            nw_tx.add_metric(['lan'], 1e6 * float(m.group(1)))

        m = re.match(r'(\d+(?:\.\d+)?)M Bytes', self.__sysinfo[0]['WSendPkt'])
        if m:
            nw_tx.add_metric(['wan'], 1e6 * float(m.group(1)))

        yield nw_tx

        nw_rx = prometheus_client.core.CounterMetricFamily('hitron_network_receive_bytes', '', labels=['device'])

        m = re.match(r'(\d+(?:\.\d+)?)M Bytes', self.__sysinfo[0]['LRecPkt'])
        if m:
            nw_rx.add_metric(['lan'], 1e6 * float(m.group(1)))

        m = re.match(r'(\d+(?:\.\d+)?)M Bytes', self.__sysinfo[0]['WRecPkt'])
        if m:
            nw_rx.add_metric(['wan'], 1e6 * float(m.group(1)))

        yield nw_rx


    def collect_sysinfo(self):
        yield prometheus_client.core.InfoMetricFamily('hitron_system', '', value={
            'serial_number': self.__sysinfo[0]['serialNumber'],
            'software_version': self.__sysinfo[0]['swVersion'],
            'hardware_version': self.__sysinfo[0]['hwVersion'],
            'model_name': self.__system_model['modelName'],
        })


    def collect_docsis(self):
        bpi = {}
        for element in self.__cminit[0]['bpiStatus'].split(','):
            k, _, v = element.strip().partition(':')
            bpi[k.lower()] = v.lower()
        yield prometheus_client.core.InfoMetricFamily('hitron_cm_bpi', 'Cable Modem Baseline Privacy Interface', value=bpi)
