# This is a two-stage build process. The first 'builder' container creates a
# venv into which the application's dependencies are installed. Then a wheel of
# the application is built and it too is installed into the venv.
#
FROM quay.io/centos/centos:stream9-minimal as builder

RUN \
  microdnf -y --nodocs --setopt=install_weak_deps=0 install \
    python3 \
    python3-pip \
  && microdnf -y clean all

# Mouting ~/.cache/pip as a cache volume causes micropipenv to fail to build
# wheels for gssapi/ldap; so let's just disable caching altogether.
#
# PIP_ROOT_USER_ACTION is implemented in Pip 22.1; that's not in RHEL 9 at this
# time, but I'll leave it set in anticipation.
#
ENV PIP_NO_CACHE_DIR=off PIP_ROOT_USER_ACTION=off

RUN python3 -m pip install build micropipenv[toml]

WORKDIR /opt/app-build

COPY pyproject.toml poetry.lock .

# We activate the app's venv so that micropipenv will install into it instead
# of the system Python environment.
#
# micropipenv installs all extra packages by default, so we don't need to
# specify -E freeipa-vault,container as we would with poetry.
#
RUN python3 -m venv /opt/app-root/venv \
  && source /opt/app-root/venv/bin/activate \
  && /usr/bin/python3 -m micropipenv install --deploy

COPY src src
COPY dist dist

ARG build_wheel=1

RUN \
  set -eux -o pipefail; \
  if [[ $build_wheel -ne 0 ]]; then \
    python3 -m build -w; \
  fi

RUN /opt/app-root/venv/bin/python3 -m pip install --no-deps dist/*.whl

# In the second stage, a minimal set of OS packages required to run the
# application is installed, and then the venv is copied from the 'builder'
# container.
#
# This saves about 200 MiB of disk space, as there's no need to include gcc and
# header files in the app's container (or at least it did back when we needed
# to build wheels such as 'gssapi' at 'poetry install' time.
#
FROM quay.io/centos/centos:stream9-minimal

# Installing ipa-client would pull in ~157 packages, nearly all of which are
# not needed for vault-retriete.py to operate. Here we install only the minimum
# set of dependencies to get the script to work.
RUN \
  set -eux -o pipefail; \
  microdnf=(microdnf -y --nodocs --setopt=install_weak_deps=0); \
  "${microdnf[@]}" install \
    python3; \
  install -d /root/rpms; \
  ( \
    cd /root/rpms; \
    "${microdnf[@]}" download \
        ipa-client \
        python3-cffi \
        python3-cryptography \
        python3-decorator \
        python3-dns \
        python3-gssapi \
        python3-ipaclient \
        python3-ipalib \
        python3-netaddr \
        python3-pyasn1 \
        python3-pyasn1-modules \
        python3-qrcode-core \
        python3-setuptools \
        python3-six \
      ; \
      rpm -iv --nodeps --excludedocs *.rpm; \
  ); \
  rm -rvf /root/rpms; \
  microdnf -y clean all;

WORKDIR /opt/app-root

COPY --from=builder /opt/app-root/venv /opt/app-root/venv

ENV \
  PYTHONUNBUFFERED=1 \
  GUNICORN_CMD_ARGS="-b 0.0.0.0:9938 --access-logfile=-"

CMD [ \
  "/opt/app-root/venv/bin/gunicorn", \
  "hitron_exporter:app" \
]

EXPOSE 9938

LABEL \
  org.opencontainers.image.authors="Sam Morris <sam@robots.org.uk>" \
  org.opencontainers.image.description="Hitron CGN series Prometheus exporter" \
  org.opencontainers.image.title="hitron-exporter" \
  org.opencontainers.image.vendor="Sam Morris <sam@robots.org.uk>"

USER 1001:0

# vim: ts=8 sts=2 sw=2 et
