FROM registry.access.redhat.com/ubi9/ubi-minimal

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

RUN python3 -m venv /opt/app-root/venv-micropipenv \
  && /opt/app-root/venv-micropipenv/bin/python -m pip install micropipenv[toml]

RUN install -d /opt/app-root/src

WORKDIR /opt/app-root/src

COPY hitron_exporter hitron_exporter

COPY pyproject.toml poetry.lock .

RUN python3 -m venv /opt/app-root/venv-app

# micropipenv installs all extra packages by default, so we don't need to
# specify -E freeipa-vault,container as we would with poetry.
#
# For some reason mouting ~/.cache/pip as a cache volume causes micropipenv to
# fail to build gssapi/ldap wheels. So instead we wipe the cache manually after
# installing. We did try the --no-cache pip option, but even with that option
# provided, there are still a couple of files cached!
#
RUN source /opt/app-root/venv-app/bin/activate \
  && /opt/app-root/venv-micropipenv/bin/python -m micropipenv install --deploy

CMD /opt/app-root/venv-app/bin/gunicorn -b 0.0.0.0:9938 hitron_exporter:app

EXPOSE 9938

LABEL org.opencontainers.image.source=https://github.com/yrro/hitron-exporter

# vim: ts=8 sts=2 sw=2 et
