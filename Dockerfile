FROM debian:trixie-slim

# source links the ghcr.io package to its GitHub repository; the build adds the version
LABEL org.opencontainers.image.title="LiteBlox" \
      org.opencontainers.image.description="A web console for BIND9, Kea DHCP and chrony on a home or small network" \
      org.opencontainers.image.source="https://github.com/dorkbrain/liteblox" \
      org.opencontainers.image.url="https://liteblox.dorkbrain.com" \
      org.opencontainers.image.documentation="https://liteblox.dorkbrain.com/docs/" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Dorkbrain"

# bind9-utils: named-checkzone/named-checkconf for validation; git: zone history;
# openssh-client: ssh-keygen/known_hosts handling for node bootstrap
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       python3 python3-venv bind9-utils git openssh-client ca-certificates tzdata \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/liteblox
COPY pyproject.toml VERSION README.md LICENSE ./
COPY liteblox ./liteblox
COPY agent ./agent
RUN python3 -m venv /opt/liteblox/venv \
  && /opt/liteblox/venv/bin/pip install --no-cache-dir . \
  && rm -rf /opt/liteblox/liteblox /opt/liteblox/agent

# non-root uid from compose has no home dir; git and ssh want somewhere writable
ENV HOME=/tmp \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/liteblox/venv/bin:$PATH \
    LITEBLOX_DATA=/data \
    LITEBLOX_BACKUPS=/backups

EXPOSE 53530 53443

# kept for docker-format builds; compose files also declare it (podman OCI builds drop this)
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["liteblox", "healthcheck"]

# never root by default: compose's `user:` (or `docker run --user`) still picks the uid that owns /data
USER 1000:1000

CMD ["liteblox", "serve"]
