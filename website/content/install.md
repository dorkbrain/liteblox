title: Install LiteBlox: requirements, downloads and setup
description: What LiteBlox needs, the current container image and source downloads with their checksums, and how to install and upgrade it with Docker Compose.

# Install LiteBlox

## Requirements

- **The LiteBlox host:** Docker with the compose plugin, or podman. Any small machine or VM, x86-64 or 64-bit ARM (a Raspberry Pi 4 or 5 with a 64-bit OS works). Its only trip to the internet is IPAM's weekly MAC vendor list.
- **The servers (nodes):** Debian (13 is what it's tested on; a scanner also ran on Ubuntu 24.04) with a fixed address, a sudo account for setup, and Python 3.9 or newer. A VM with 2 cores and 1 GB of RAM is plenty: running BIND, Kea and chrony together uses about 330 MB.
- **Internet access on the servers:** they install BIND, Kea and chrony from Debian's APT repositories when you set up each module, so they need to reach them.
- LiteBlox needs to reach each server on TCP 22 (setup) and TCP 8530 (the agent), and DNS servers on port 53. Your browser reaches LiteBlox on TCP 53530.

## Downloads

Version {{version}}. Older versions are in [all downloads](/downloads/).

{{downloads}}

Pick the image for the LiteBlox host's processor: `uname -m` prints `x86_64` for the x86-64 one and `aarch64` for the ARM64 one. 32-bit ARM (`armv7l`) isn't supported. Both load as the same name.

SHA-256 checksums:

```
{{checksums}}
```

## Install

The image is on GitHub's container registry, `ghcr.io/dorkbrain/liteblox`, for x86-64 and ARM64: docker pulls the one for your machine.

```bash
mkdir -p /srv/liteblox && cd /srv/liteblox
mkdir -p data backups && sudo chown 1000:1000 data backups
```

Save this as `/srv/liteblox/docker-compose.yaml`:

```yaml
services:
  liteblox:
    image: ghcr.io/dorkbrain/liteblox:{{version}}
    container_name: liteblox
    restart: unless-stopped
    user: "1000:1000"
    environment:
      - TZ=America/Detroit          # your time zone
    volumes:
      - ./data:/data
      - ./backups:/backups
    ports:
      - "53530:53530"
      - "53443:53443"               # HTTPS, once it's on in Settings → HTTPS
    healthcheck:
      test: liteblox healthcheck
      interval: 30s
      timeout: 3s
```

```bash
docker compose up -d
docker compose exec liteblox liteblox user add admin
```

**Without a registry** (a machine with no internet access, say): download the image file above for your processor, load it, and use the name it prints on the `image:` line instead:

```bash
docker load -i liteblox-image-v{{version}}-amd64.tar.gz      # or -arm64; Loaded image: localhost/liteblox:{{version}}
```

Browse to `http://HOST:53530` and log in. A new install first asks which modules to run. Then follow the [Quick start](/docs/quick-start/): prepare a server, add it as a node, and LiteBlox sets it up. Anywhere beyond a trusted home network, turn on its own HTTPS under **Settings → HTTPS** ([HTTPS](/docs/https/)) or put it behind an HTTPS reverse proxy ([Installing and upgrading](/docs/install/#https)).

## Upgrading

Back up `/srv/liteblox/data`, change the version on the `image:` line, then `docker compose pull && docker compose up -d` (or `docker load` the new image file and use its name). The image is also tagged by minor and major version (`:X.Y`, `:X`) and `:latest`: with `:X.Y` on the `image:` line, `docker compose pull` brings in that version's patch releases. If the Nodes page marks a node **upgrade**, run **Repair / upgrade agent** on it. Skipping versions is fine: every database change in between is applied on start. The text file above has the details, including how to go back.

See the [changelog](/changelog/) for what each version changed.
