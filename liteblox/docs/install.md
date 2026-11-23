# Installing and upgrading

## What the LiteBlox host needs

- docker with the compose plugin (`docker compose`); podman works too, see [With podman](#with-podman)
- an x86-64 or 64-bit ARM processor (a Raspberry Pi 4 or 5 with a 64-bit OS works), with the image built for it
- network access to every node on:

  | Port | Why |
  |---|---|
  | TCP 22 | setup and agent upgrades over SSH |
  | TCP 8530 | the agent on each node |
  | UDP + TCP 53 | LiteBlox asks each node which serial it serves, checks that its zones still answer after a change, and reads and updates dynamic zones |

## Run it

The image is on GitHub's container registry as `ghcr.io/dorkbrain/liteblox`, built for x86-64 and 64-bit ARM; docker pulls the one for your machine. 32-bit ARM isn't supported.

Create a directory for LiteBlox and save this as `docker-compose.yaml`, with the version you want on the `image:` line:

```yaml
services:
  liteblox:
    image: ghcr.io/dorkbrain/liteblox:X.Y.Z
    container_name: liteblox
    restart: unless-stopped
    user: "1000:1000"
    environment:
      - TZ=America/Detroit
      # - FORWARDED_ALLOW_IPS=192.168.1.x   # your reverse proxy, if any (see HTTPS below)
    volumes:
      - ./data:/data
      - ./backups:/backups
    ports:
      - "53530:53530"
      - "53443:53443"     # HTTPS, once it's on (see HTTPS below)
    healthcheck:
      test: liteblox healthcheck
      interval: 30s
      timeout: 3s
```

```bash
mkdir -p data backups
sudo chown 1000:1000 data backups
docker compose up -d
docker compose ps            # "healthy" after the first health check, about 30 seconds
```

- **`user`**: LiteBlox runs as uid 1000, so `./data` and `./backups` must be owned by uid 1000 (the `chown` above). The image runs as uid 1000 even without this line, never as root. To run it as another user, change `user:` and own the folders accordingly.
- **`TZ`**: the time zone for the daily backup time and the times shown in logs.
- **`./backups`** can be any mount, for example an NFS share on a NAS.

## With podman

The same file works with `podman compose`. With rootless podman, add `userns_mode: "keep-id"` under `user:` (the line is in the project's file, commented out): it maps uid 1000 to your own user, so the folders stay owned by you and need no `chown`. Every `docker compose` command on these pages works as `podman compose`.

## First admin

LiteBlox has no default account. Create the first one from the host:

```bash
docker compose exec liteblox liteblox user add admin
```

Then browse to `http://HOST:53530`. Add more accounts on the **Users** page, or with the [command line](/help/reference#accounts).

### Without a registry

On a host that can't reach ghcr.io, download the image file for its processor from the website's downloads: `-amd64` for x86-64 (`uname -m` prints `x86_64`) or `-arm64` for 64-bit ARM (`aarch64`). Load it, and put the name it prints on the `image:` line:

```bash
docker load -i liteblox-image-vX.Y.Z-amd64.tar.gz      # or -arm64; prints the image name: localhost/liteblox:X.Y.Z
```

## HTTPS

LiteBlox serves plain HTTP on port 53530. Passwords, including the one used for node setup, cross the network, so anywhere beyond a trusted home network use HTTPS, one of two ways:

- **LiteBlox's own HTTPS** on port 53443: publish the port (the `53443` line above) and turn it on under **Settings → HTTPS**, with a self-signed certificate, one you import, or one your own Let's Encrypt tooling renews. See [HTTPS](/help/https).
- **A TLS reverse proxy** (Caddy, nginx, Traefik, Nginx Proxy Manager…) pointing at port 53530, as below.

With a reverse proxy:

1. Set `secure_cookies = true` in `./data/config.toml`.
2. Set `FORWARDED_ALLOW_IPS` to the address the proxy's requests come **from**, in the compose file, so LiteBlox trusts its `X-Forwarded-*` headers. List several separated by commas.
    - A proxy on another machine: that machine's address.
    - A proxy in a container on the **same docker host** (Nginx Proxy Manager, say): its requests arrive from the docker network's **gateway**, not from the host's LAN address. Find it with `docker network inspect NETWORK -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'` (`docker network ls` lists the networks; LiteBlox's is usually the compose folder's name plus `_default`). Listing both is fine, for example `FORWARDED_ALLOW_IPS=192.168.192.1,192.168.1.10`.

    Without it, LiteBlox doesn't know it's on HTTPS and every visitor looks like the proxy:
    - Add node warns that the password would cross the network in plain text;
    - the API's `/api/docs` link and the token page's example URL start with `http://`;
    - the audit log shows the proxy's address for everyone, and the [login throttle's](/help/security#who-can-use-liteblox) per-address limit (20 failures in 15 minutes) counts everyone's failures together. The per-account limit still applies either way.
3. Restart: `docker compose up -d --force-recreate`.

The node setup page warns when it isn't served over HTTPS.

## Settings

`./data/config.toml` is created on first start. It holds only app settings (session length, cookies, backup schedule and retention); nodes and zones live in the database and are managed in the UI. See the [settings reference](/help/reference#configtoml). Restart the container after editing it.

## What to back up

Everything LiteBlox knows is in two folders:

- **`./data`**: the database (accounts, nodes, zones, keys, DHCP settings, publish log), the zone history (git), the certificate authority that the agents and a DHCP failover pair trust, and the session key. **Treat it as secret.**
- **`./backups`**: the node backups.

Copying `./data` while LiteBlox is stopped is the simplest safe backup. Restoring it on a new host and starting the container brings LiteBlox back, and the agents still trust it.

Keep a copy somewhere other than the LiteBlox host. Without one, a new LiteBlox can still rebuild most of its data from the nodes: see [Disaster recovery](/help/backups#disaster-recovery).

## Upgrading

Change the version on the `image:` line in `docker-compose.yaml`, then:

```bash
docker compose pull && docker compose up -d
```

Besides each version (`:X.Y.Z`), the image is tagged `:X.Y`, `:X` and `:latest`. With `:X.Y` on the `image:` line, `docker compose pull` picks up that version's patch releases without editing the file. Without a registry, `docker load` the new image file instead of pulling, and put the name it prints on the `image:` line.

Database changes are applied automatically on start. Browsers pick up new styles and scripts on their own.

**Skipping versions is fine:** each change to the database is applied in order on start, from whatever version the data is at, so 3.3 → 4.0 runs every step in between. Read the notes for each version you skip, though (below and in the changelog): for example, a new agent in any of them still needs **Repair / upgrade agent** once, on the version you land on.

**Before upgrading, copy `./data`** (with LiteBlox stopped, or right after a backup). There's no going back on the same data: an older LiteBlox won't start on a database a newer one has changed. It stops with `ERROR: the database (…) is schema vN, written by a newer LiteBlox`, and you either run the newer image again or put the copy back:

```bash
docker compose down
cp -a data data.before-4.0
# change the image: line and docker compose pull, then
docker compose up -d
```

### Upgrading an agent

A new LiteBlox version may ship a new agent. The Nodes list then marks those nodes **upgrade**.

- **Upgrade agent** (on the node's page, or **Upgrade all agents** on the Nodes list) sends the new agent over the agent's own connection, so no SSH or setup account is needed. The agent saves it, restarts, and a small installer that systemd runs as root just before the agent starts puts it in place. It's done one node at a time, and each agent is down for a few seconds; BIND, Kea and chrony keep running.
    - The installer takes only a file the agent user wrote, read without following links. It must match the checksum LiteBlox sent, parse as Python and be a LiteBlox agent, and must not be older than the agent it replaces.
    - If the new agent doesn't start twice in a row, the old one comes back on its own, and the job says so.
    - Only the agent's own code changes this way. Its systemd unit, the installer, its config and its certificates change only by Repair.
- **Repair / upgrade agent** (over SSH, with the setup account) is still needed the first time, to put the installer on a node, and whenever a version changes more than the agent's code: the node's page says which. It also goes back to an older agent, which Upgrade agent refuses. Nothing that's already in place is changed.

## Upgrading to 4.6

4.6 adds LiteBlox's own [HTTPS](/help/https), off until you turn it on. To use it, add the port to `docker-compose.yaml` and recreate the container:

```yaml
    ports:
      - "53530:53530"
      - "53443:53443"
```

Nothing else changes, and the nodes need no Repair.

## Upgrading to 4.5

4.5 lets LiteBlox upgrade agents itself ([Upgrading an agent](#upgrading-an-agent)). Run **Repair / upgrade agent** on each node once more: that puts the installer in place. From then on, **Upgrade agent** does it without SSH.

The image now runs as uid 1000 by default, as `docker-compose.yaml` always did, so `./data` and `./backups` must be owned by uid 1000 (or by the user in your `user:` line) even without one.

## Upgrading to 4.0

4.0 makes the parts [modules](/help/modules). An upgraded install starts with all four on, its nodes all BIND nodes, and DHCP registering clients through LiteBlox's DNS as before (or Off, if no key was set), so nothing changes until you choose. Run **Repair / upgrade agent** on each node: the agent learned nodes without BIND.

## Upgrading to 3.0

3.0 adds DHCP. After starting the new image, run **Repair / upgrade agent** on each node (the agent learned Kea). Nothing else changes: DHCP is set up only on the nodes where you choose **Set up DHCP**, and a DNS-only node stays as it was. See [DHCP (Kea)](/help/dhcp).

## Upgrading from 1.x

LiteBlox 2 changes how it runs BIND: instead of editing zone files on servers that are all primaries ("dual-master"), it takes over each server's whole BIND configuration, and one server is the primary for every zone. Your zones, their history and your accounts carry over. After pulling the new image:

1. **Upgrade every agent:** on each node, **Repair / upgrade agent**.
2. **Take over every node:** on each node's page, **Take over** shows a preview of the configuration LiteBlox would write: your options, ACLs, keys and zones, each zone file's new place in `/etc/bind/liteblox/`, and proof that it's equivalent to what the server runs now. Anything LiteBlox can't represent yet (views, for example) is listed and blocks the takeover until you've removed it. **Take over** switches the node over; its own files move to `/etc/bind/pre-liteblox/`. See [Bringing in existing servers](/help/existing-servers#2-take-over-a-server-with-its-own-config).
3. **Pick the primary:** on **Nodes**, **Make ns1 the primary** (whichever you like). The other nodes become its secondaries and transfer every zone from it.

Until a node is taken over, LiteBlox doesn't change it: publishing and zone changes refuse it with "take over first". The `include "/etc/bind/named.conf.liteblox";` line and the Adopt step of 1.x are gone; the takeover replaces both.

## Checking the install

```bash
docker compose exec liteblox liteblox check
```

prints the version, the data and backups folders, the database schema version, and whether `named-checkzone`, `named-checkconf` and `git` are available (they're in the image).
