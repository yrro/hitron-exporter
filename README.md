# hitron exporter

A [Prometheus](https://prometheus.io/) exporter for the Hitron CGN series CPE.

The Hitron CGN series CPE are a combination cable modem, Wi-Fi access points,
Analog Telephone Adapter, router, firewall device.

Tested with my CGNV4-FX4 as provided by [Virgin Media
business](https://www.virginmediabusiness.co.uk/help-and-advice/products-and-services/hitron-router-guide/).

If you've tried it with another model, [please let me
know](mailto:sam@robots.org.uk). And, of course, pull requests are welcome!

## Features

This exporter uses the [multi-target exporter
pattern](https://prometheus.io/docs/guides/multi-target-exporter/), where the
list of CPE devices and parameters for probing them live in Prometheus's config
file.

Credentials can be stored securely in a [FreeIPA](https://www.freeipa.org/)
vault. At some point I'll add the ability to retrieve them from a config file
as well.

Communcation with the CPE device is secured by TLS; the TLS server certificate
fingerprint is checked against the value configured in Prometheus.

Written in [Python](https://python.org/) (or is this an anti-feature?)

## Sample metrics

Metric definitions are not yet final!

```
# HELP hitron_channel_upstream_signal_strength_dbmv 
# TYPE hitron_channel_upstream_signal_strength_dbmv gauge
hitron_channel_upstream_signal_strength_dbmv{channel="2",frequency="39400000",port="1"} 35.75
hitron_channel_upstream_signal_strength_dbmv{channel="1",frequency="46200000",port="2"} 35.75
hitron_channel_upstream_signal_strength_dbmv{channel="3",frequency="32600000",port="3"} 35.5
hitron_channel_upstream_signal_strength_dbmv{channel="4",frequency="25800000",port="4"} 37.0
# HELP hitron_channel_upstream_bandwidth 
# TYPE hitron_channel_upstream_bandwidth gauge
hitron_channel_upstream_bandwidth{channel="2",frequency="39400000",port="1"} 6.4e+06
hitron_channel_upstream_bandwidth{channel="1",frequency="46200000",port="2"} 6.4e+06
hitron_channel_upstream_bandwidth{channel="3",frequency="32600000",port="3"} 6.4e+06
hitron_channel_upstream_bandwidth{channel="4",frequency="25800000",port="4"} 6.4e+06
# HELP hitron_channel_downstream_signal_strength_dbmv 
# TYPE hitron_channel_downstream_signal_strength_dbmv gauge
hitron_channel_downstream_signal_strength_dbmv{channel="9",frequency="426250000",port="1"} 16.7
hitron_channel_downstream_signal_strength_dbmv{channel="1",frequency="362250000",port="2"} 16.3
hitron_channel_downstream_signal_strength_dbmv{channel="2",frequency="370250000",port="3"} 16.2
hitron_channel_downstream_signal_strength_dbmv{channel="3",frequency="378250000",port="4"} 16.5
hitron_channel_downstream_signal_strength_dbmv{channel="4",frequency="386250000",port="5"} 16.3
hitron_channel_downstream_signal_strength_dbmv{channel="5",frequency="394250000",port="6"} 16.5
hitron_channel_downstream_signal_strength_dbmv{channel="6",frequency="402250000",port="7"} 16.3
hitron_channel_downstream_signal_strength_dbmv{channel="7",frequency="410250000",port="8"} 16.6
hitron_channel_downstream_signal_strength_dbmv{channel="8",frequency="418250000",port="9"} 16.4
hitron_channel_downstream_signal_strength_dbmv{channel="10",frequency="434250000",port="10"} 16.6
hitron_channel_downstream_signal_strength_dbmv{channel="11",frequency="442250000",port="11"} 16.7
hitron_channel_downstream_signal_strength_dbmv{channel="12",frequency="450250000",port="12"} 16.8
hitron_channel_downstream_signal_strength_dbmv{channel="13",frequency="458250000",port="13"} 16.7
hitron_channel_downstream_signal_strength_dbmv{channel="14",frequency="466250000",port="14"} 16.7
hitron_channel_downstream_signal_strength_dbmv{channel="15",frequency="474250000",port="15"} 16.6
hitron_channel_downstream_signal_strength_dbmv{channel="16",frequency="482250000",port="16"} 16.4
hitron_channel_downstream_signal_strength_dbmv{channel="17",frequency="490250000",port="17"} 16.2
hitron_channel_downstream_signal_strength_dbmv{channel="18",frequency="498250000",port="18"} 16.1
hitron_channel_downstream_signal_strength_dbmv{channel="19",frequency="506250000",port="19"} 16.0
hitron_channel_downstream_signal_strength_dbmv{channel="20",frequency="514250000",port="20"} 16.2
hitron_channel_downstream_signal_strength_dbmv{channel="21",frequency="522250000",port="21"} 16.2
hitron_channel_downstream_signal_strength_dbmv{channel="22",frequency="530250000",port="22"} 16.4
hitron_channel_downstream_signal_strength_dbmv{channel="23",frequency="538250000",port="23"} 16.3
hitron_channel_downstream_signal_strength_dbmv{channel="24",frequency="546250000",port="24"} 16.5
# HELP hitron_channel_downstream_snr 
# TYPE hitron_channel_downstream_snr gauge
hitron_channel_downstream_snr{channel="9",frequency="426250000",port="1"} 40.366
hitron_channel_downstream_snr{channel="1",frequency="362250000",port="2"} 40.366
hitron_channel_downstream_snr{channel="2",frequency="370250000",port="3"} 40.946
hitron_channel_downstream_snr{channel="3",frequency="378250000",port="4"} 40.366
hitron_channel_downstream_snr{channel="4",frequency="386250000",port="5"} 40.946
hitron_channel_downstream_snr{channel="5",frequency="394250000",port="6"} 40.946
hitron_channel_downstream_snr{channel="6",frequency="402250000",port="7"} 40.946
hitron_channel_downstream_snr{channel="7",frequency="410250000",port="8"} 40.366
hitron_channel_downstream_snr{channel="8",frequency="418250000",port="9"} 40.946
hitron_channel_downstream_snr{channel="10",frequency="434250000",port="10"} 40.366
hitron_channel_downstream_snr{channel="11",frequency="442250000",port="11"} 40.946
hitron_channel_downstream_snr{channel="12",frequency="450250000",port="12"} 40.946
hitron_channel_downstream_snr{channel="13",frequency="458250000",port="13"} 40.946
hitron_channel_downstream_snr{channel="14",frequency="466250000",port="14"} 40.366
hitron_channel_downstream_snr{channel="15",frequency="474250000",port="15"} 40.366
hitron_channel_downstream_snr{channel="16",frequency="482250000",port="16"} 40.366
hitron_channel_downstream_snr{channel="17",frequency="490250000",port="17"} 40.366
hitron_channel_downstream_snr{channel="18",frequency="498250000",port="18"} 40.946
hitron_channel_downstream_snr{channel="19",frequency="506250000",port="19"} 40.366
hitron_channel_downstream_snr{channel="20",frequency="514250000",port="20"} 40.946
hitron_channel_downstream_snr{channel="21",frequency="522250000",port="21"} 40.946
hitron_channel_downstream_snr{channel="22",frequency="530250000",port="22"} 40.946
hitron_channel_downstream_snr{channel="23",frequency="538250000",port="23"} 40.946
hitron_channel_downstream_snr{channel="24",frequency="546250000",port="24"} 40.366
# HELP hitron_system_uptime_seconds_total 
# TYPE hitron_system_uptime_seconds_total counter
hitron_system_uptime_seconds_total 284820.0
# HELP hitron_traffic_lan_sent_bytes_total 
# TYPE hitron_traffic_lan_sent_bytes_total counter
hitron_traffic_lan_sent_bytes_total 3.3833e+09
# HELP hitron_traffic_lan_recv_bytes_total 
# TYPE hitron_traffic_lan_recv_bytes_total counter
hitron_traffic_lan_recv_bytes_total 8.699e+08
# HELP hitron_traffic_wan_sent_bytes_total 
# TYPE hitron_traffic_wan_sent_bytes_total counter
hitron_traffic_wan_sent_bytes_total 1.1021e+09
# HELP hitron_traffic_wan_recv_bytes_total 
# TYPE hitron_traffic_wan_recv_bytes_total counter
hitron_traffic_wan_recv_bytes_total 4.9073e+09
# HELP hitron_system_info 
# TYPE hitron_system_info gauge
hitron_system_info{hardware_version="2D",model_name="CGNV4-FX4",serial_number="ABC123",software_version="4.5.10.201-CD-UPC"} 1.0
# HELP hitron_cm_bpi_info Cable Modem Baseline Privacy Interface
# TYPE hitron_cm_bpi_info gauge
hitron_cm_bpi_info{auth="authorized",tek="operational"} 1.0
```

## How to run

If you're into containers:

```
$ podman run --name hitron-exporter --replace --host=net ghcr.io/yrro/hitron-exporter:latest
```

If you're not into containers, you need [Poetry](https://python-poetry.org/)
which will take care of creating a venv, installing dependencies, etc.

```
$ poetry install

$ poetry run gunicorn -b 0.0.0.0:9938 hitron_exporter:app
```

Once the exporter is running, use an HTTP client such as
[HTTPie](https://httpie.io/) to probe for metrics:

```
$ http localhost:9938/probe address==192.2.0.1 usr==admin pwd==hunter2
```

If you don't have HTTPie installed, prepend `poetry run` to that command to use
the copy installed by Poetry.

## Transport security

HTTPS is used to protect the confidentiality and integrity of communictions
with the CPU device, however the modem's TLS server certificate can't be
verified in the usual way.

We can work around this by telling the exporter to check the fingerprint of the
TLS server certificate against a known good fingerprint.

When you probe for metrics without providing a `fingerprint` parameter, the
exporter will log the fingerprint of the TLS server certificate that it
recieves from the target.

So all you need to do is take note of that log message, and then provide the
fingerprint at probe time:

```
$ http localhost:9938/probe address==192.2.0.1 usr==admin pwd==hunter2 fingerprint==A3:2E:C1:77:83:16:5A:FD:87:B2:E2:B9:C6:26:E8:FB:1B:A3:9D:4C:28:A3:AB:A0:CD:50:08:6D:FC:E7:DF:10
```

When a probe specifies `fingerprint`, the exporter will refuse to connect to
connect to an attacker interposed between the exporter and the CPE device.

## Credential security

Passing credentials to programs on the command line is not best practice. If
you use [FreeIPA](https://www.freeipa.org/) then you have the option of storing
the credentials in vaults associated with a service.

This requires a few extra libraries which are installed when you run:

```
$ poetry install -E freeipa-vault
```

(These are included in the container image by default).

Create the following objects in the FreeIPA directory:

 * A host that acts as the CPE device's identity: `host/cm-hitron.example.com`
 * A `usr` vault that stores the username
 * A `pwd` vault that stores the password
 * A service that acts as `hitron-exporter`'s identity: `HTTP/hitron-exporter.example.com`

Then grant `HTTP/hitron-exporter.example.com` permission to read the cable
modem's vaults.

```
$ ipa host-add cm-hitron.example.com --force

$ ipa vault-create usr --service=host/cm-hitron.example.com

$ ipa vault-create pwd --service=host/cm-hitron.example.com

$ echo -e admin | ipa vault-archive usr --service=host/cm-hitron.example.com

$ echo -e hunter2 | ipa vault-archive pwd --service=host/cm-hitron.example.com

$ ipa service-add HTTP/hitron-exporter.example.com --force --skip-host-check

$ ipa vault-add-member usr --service=host/cm-hitron.example.com --services=HTTP/hitron-exporter.example.com

$ ipa vault-add-member pwd --service=host/cm-hitron.example.com --services=HTTP/hitron-exporter.example.com
```

Finally, create a *keytab* which the exporter will use to authenticate to the
FreeIPA servers.

```
$ ipa-getkeytab -p HTTP/hitron-exporter.example.com -k /tmp/hitron-exporter.keytab
```

We're finally ready to run the exporter...

```
$ KRB5_CLIENT_KTNAME=/tmp/hitron-exporter.keytab KRB5CCNAME=MEMORY: poetry run gunicorn -b 0.0.0.0:9938 hitron_exporter:app
```

... and test it:

```
$ poetry run http localhost:9938/probe address==192.2.0.1 fingerprint==A3:2E:C1:77:83:16:5A:FD:87:B2:E2:B9:C6:26:E8:FB:1B:A3:9D:4C:28:A3:AB:A0:CD:50:08:6D:FC:E7:DF:10
```

To debug, try setting the environment variable `KRB5_TRACE=/dev/stderr` and
reading the log messages produced. If there aren't any Kerberos-related
messages logged, check:

 * `KRB5_CLIENT_KTNAME` is set correctly
 * The keytab is readable: print its contents with
  `klist -k /tmp/hitron-exporter.keytab`

### Pulling credentials from FreeIPA in a container

Here's what's needed:

 * Mount `/etc/ipa` from the host inside the guest
 * Mount the keytab from the host inside the guest
 * Set `KRB5_CLIENT_KTNAME` to point to the keytab inside the container

Make sure the keytab file is readable inside the container; MIT Kerberos

In addition, I recommend:

 * Set `KRB5CCNAME=MEMORY:` since there's no reason to share a credentials
   cache between multiple processes; with the default value I get an exception
   thrown:
  `ipalib.errors.KerberosError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (1): Operation not permitted`
 * Set `KRB5_TRACE=/dev/stderr` while debugging and read the log messages
 * If there are no Kerberos-related log messages, check `KRB5_CLIENT_KTNAME` is
   readable from within the container; confirm with
   `podman exec hitron-exporter hexdump -C $KRB5_CLIENT_KTNAME`

For example:

```
$ podman run -v /etc/ipa:/etc/ipa -v /etc/hitron-exporter.keytab:/etc/hitron-exporter.keytab --env KRB5CCNAME=MEMORY: --env KRB5_TRACE=/dev/stderr --env KRB5_CLIENT_KTNAME=/etc/hitron-exporter.keytab --net=host --name hitron-exporter --replace --rm hitron-exporter:latest
```

## Using your own Gunicorn settings in a container

[Gunicorn settings](https://docs.gunicorn.org/en/latest/settings.html) can be
specified via the `GUNICORN_CMD_ARGS` environment variable. This will override
the default settings baked into the container image, so you shoudl use the
following command, replacing `...` with your preferred settings.

```
$ podman run --name hitron-exporter --net=host --rm --replace --env GUNICORN_CMD_ARGS='--bind=0.0.0.0:9938 --access-logfile=- ...' ghcr.io/yrro/hitron-exporter:latest
```

## How to develop

Run a development web server:

```
$ FLASK_DEBUG=1 FLASK_APP=hitron_exporter:app poetry run flask run
```

Probe for metrics:

```
$ poetry run http localhost:9938/probe address==192.2.0.1 usr==admin pwd==hunter2 fingerprint==A3:2E:C1:77:83:16:5A:FD:87:B2:E2:B9:C6:26:E8:FB:1B:A3:9D:4C:28:A3:AB:A0:CD:50:08:6D:FC:E7:DF:10
```

## Building the container image

You need [source-to-image](https://github.com/openshift/source-to-image).

To build using [Docker](https://www.docker.com/):

```
$ s2i build . registry.access.redhat.com/ubi8/python-39 hitron-exporter
```

To build using [Podman](https://podman.io/):

```
$ rm -rf /tmp/hitron-exporter-docker-context \
    && mkdir /tmp/hitron-exporter-docker-context
    && s2i build . registry.access.redhat.com/ubi8/python-39 hitron-exporter --as-dockerfile /tmp/hitron-exporter-docker-context/Dockerfile \
    && podman build /tmp/hitron-exporter-docker-context -t ghcr.io/yrro/hitron-exporter:latest
```

## Alternatives

[cfstras/hitron-exporter](https://github.com/cfstras/hitron-exporter), is
another Prometheus exporter for Hitron CGNV4 CPE devices. It's written in Go.

[tcpipuk/Hitron](https://github.com/tcpipuk/Hitron), a Python module for
interacting with Hitron CGNV4 CPE devices, has some code that makes sense of
the DOCSIS and GRE status data. I might use it to create stateset/enum metrics
for monitoring the status of these connections.


