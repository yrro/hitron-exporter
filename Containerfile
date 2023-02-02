FROM registry.access.redhat.com/ubi9/ubi-minimal AS builder

RUN --mount=type=cache,target=/var/cache/yum \
  microdnf -y --nodocs --setopt=install_weak_deps=0 install \
    python3 python3-pip python3-devel krb5-devel gcc openldap-devel

# Mouting ~/.cache/pip as a cache volume causes micropipenv to fail to build
# wheels for gssapi/ldap; so let's just disable caching altogether.
#
# PIP_ROOT_USER_ACTION is implemented in Pip 22.1; that's not in RHEL 9 at this
# time, but I'll leave it set in anticipation.
#
ENV PIP_NO_CACHE_DIR=off PIP_ROOT_USER_ACTION=off

RUN python3 -m pip install micropipenv[toml]

WORKDIR /opt/app-build

COPY pyproject.toml poetry.lock .

# micropipenv installs all extra packages by default, so we don't need to
# specify -E freeipa-vault,container as we would with poetry.
#
# For some reason mouting ~/.cache/pip as a cache volume causes micropipenv to
# fail to build gssapi/ldap wheels. So instead we wipe the cache manually after
# installing. We did try the --no-cache pip option, but even with that option
# provided, there are still a couple of files cached!
#
RUN python3 -m venv /opt/app-root/venv \
  && source /opt/app-root/venv/bin/activate \
  && /usr/bin/python3 -m micropipenv install --deploy


FROM registry.access.redhat.com/ubi9/ubi-minimal

RUN --mount=type=cache,target=/var/cache/yum \
  microdnf -y --nodocs --setopt=install_weak_deps=0 install \
    python3

WORKDIR /opt/app-root

COPY --from=builder /opt/app-root/venv /opt/app-root/venv

COPY hitron_exporter hitron_exporter

CMD /opt/app-root/venv/bin/gunicorn -b 0.0.0.0:9938 hitron_exporter:app

EXPOSE 9938

LABEL org.opencontainers.image.source=https://github.com/yrro/hitron-exporter

USER 1001:0

# vim: ts=8 sts=2 sw=2 et
