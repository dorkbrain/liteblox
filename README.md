# LiteBlox

> Website, documentation and downloads: **[liteblox.dorkbrain.com](https://liteblox.dorkbrain.com)**. This repository gets one commit per release; development happens in a private repository, so pull requests aren't accepted.

A web console that runs **BIND9** DNS servers for you: give it a few Debian boxes with a sudo account and it takes over their whole BIND configuration. Edit zone records row by row or many at once, review the diff and publish; set each server's options, ACLs and TSIG keys in the browser; let DHCP and ACME clients update dynamic zones; move the primary to another server when one dies. On the same servers it can run **Kea** for DHCP: subnets, pools, reservations and live leases, clients registered in DNS, and a failover pair. And it keeps track of your addresses (**IPAM**): networks and ranges, what's used and free, the devices the servers see, and the next free address on request. Each server's files are backed up so a dead one can be rebuilt, and if LiteBlox itself is lost, a new one can re-adopt the servers.

Each part is a **module** you can switch off (4.0): run all four, DHCP only with the DNS servers you already have (Kea registers clients there), or just the address list, with small **scanner** nodes that only report who is on each network.

LiteBlox is built for a home or small network: one server is the **primary** for every zone and the others are its **secondaries**, kept up to date with NOTIFY and incremental transfers.

> **Status: 4.7.** Full BIND takeover (fresh servers, or existing ones with their own config, proven equivalent first), primary/secondary with promote and automatic demotion, forward/reverse/forwarding-only zones, dynamic zones with TSIG keys and per-zone grants, per-node server settings and global ACLs, config drift detection, editing with drafts and review, automatic PTR records, history with compare and restore, node backups, accounts and an audit log. **DHCP with Kea** (3.0): subnets, pools, reservations, live leases, DNS registration that follows the primary, a hot-standby failover pair, and **re-adopting** the nodes after LiteBlox's own data is lost. Then a REST API with per-user tokens (3.1), time sync with chrony (3.2), a **Dashboard** with graphs and a Jobs page (3.3), search across every zone and DHCP (3.3.2), **IPAM** (3.4), subnet tools and a light/dark switch (3.5), **modular installs** (4.0: any mix of DNS, DHCP, time and IPAM, nodes without BIND, scanner nodes) **bulk record edits** (4.1: select and act, Add many from lines or a CSV, an API batch call, moving one address everywhere, and cleaning up stale DHCP names), CSV export (4.3), built-in HTTPS (4.6) and images for x86-64 and ARM64 on ghcr.io (4.6.1, 4.7) and nodes on ARM64 too, such as a Raspberry Pi (4.7.2). Full documentation is built into the app under **Help** (`/help`, readable without logging in; sources in [liteblox/docs/](liteblox/docs/)). See [Roadmap](#roadmap).

## How it works

```
browser ──htmx──▶ LiteBlox container (FastAPI)
                    ├─ zone editor   lossless zone-file parser: edit rows, keep comments/layout
                    ├─ git repo      every published change is a commit
                    ├─ bindconf      renders each node's whole BIND config from the database
                    ├─ dhcp          renders Kea's config (subnets, reservations, DDNS, failover)
                    ├─ ipam          networks and ranges over DNS + DHCP + what the nodes see; next free, the sweep
                    ├─ health check  every minute: status, config drift, pending demotions, figures for the graphs,
                    │                the nodes' neighbour (ARP) tables
                    └─ backups       scheduled tarballs of each node's BIND files
                          │ HTTPS + mutual TLS
                ┌─────────┴─────────┐
        liteblox-agent (ns1)   liteblox-agent (ns2)    small stdlib-only Python service per node
          primary  ──NOTIFY, IXFR──▶  secondary           BIND
          Kea primary ◀─failover, TLS─▶ Kea standby  DHCP (optional), D2 registers names on the DNS primary
                                                      (or at another DNS server)
        a node without BIND: Kea and/or chrony, or only the agent (a scanner for IPAM)
```

- **LiteBlox writes the whole BIND config.** `named.conf` includes only generated files (`options.conf`, `acls.conf`, `keys.conf`, `top.conf`, `zones.conf` in `/etc/bind/liteblox/`). The agent checks each against a strict allow-list and `named-checkconf` before `rndc reconfig`. Changes go one node at a time, with DNS probes after each, and roll back everywhere if a node stops answering. Hand edits are detected within a minute (drift) and can be overwritten or kept.
- **Zone files stay the source of truth.** LiteBlox parses static zones into rows and writes them back with untouched lines left byte-for-byte. Every publish is a git commit you can compare or restore. Dynamic zones are read by AXFR and edited with guarded RFC 2136 updates, and their history is kept as snapshots.
- **One primary.** Publishes go to the primary, checked by its own `named-checkzone`, then every secondary's serial is verified. **Promote** moves the primary even when the old one is down; it's demoted when it returns, and records only it had are kept in a report.
- **Kea, the same way.** On a node with DHCP set up, LiteBlox writes `/etc/kea/kea-dhcp4.conf` and `kea-dhcp-ddns.conf`. Each change is previewed as a diff, checked by `kea-dhcp4 -t` on the node, applied one node at a time (the failover standby first) and rolled back if Kea stops answering. Leases stay in Kea and are read live.
- **No SSH for day-to-day work.** SSH is used only during setup, with temporary credentials typed into the setup wizard, to install BIND and `liteblox-agent` and take over the config. After that LiteBlox talks to the agent over mutual TLS. The agent runs as an unprivileged user in group `bind` and needs no sudo.

### What lives where

| Layer | Where |
|---|---|
| Zone contents (records) | LiteBlox's git repo; the file on the primary, copies on the secondaries |
| Zone declarations | `/etc/bind/liteblox/zones.conf`, generated per node |
| `options {}` and top-level statements | per-node server settings in LiteBlox → `options.conf`, `top.conf` |
| ACLs and TSIG keys | global in LiteBlox → `acls.conf`, `keys.conf` on every node |
| The node's original config | moved to `/etc/bind/pre-liteblox/<time>/` at takeover |
| DHCP: interfaces, subnets, reservations, DDNS, the failover pair | in LiteBlox → `/etc/kea/kea-dhcp4.conf`, `kea-dhcp-ddns.conf` (and `/etc/kea/tls/` for the pair) on each DHCP node |
| Leases | Kea's own lease file on the node; LiteBlox reads them live |
| IPAM: networks, ranges, devices, notes, devices seen | LiteBlox's database only; nothing is written to the nodes |

## Quick start

The full walkthrough, from two fresh Debian servers to forward and reverse zones on a primary and its secondary, is built into the app at **Help → Quick start** ([liteblox/docs/quick-start.md](liteblox/docs/quick-start.md)). In short:

Copy [docker-compose.yaml](docker-compose.yaml) into a directory on the host that will run LiteBlox (it pulls `ghcr.io/dorkbrain/liteblox`, for x86-64 or ARM64), then:

```bash
docker compose up -d
docker compose exec liteblox liteblox user add admin --role admin
```

`./data` and `./backups` must be owned by uid 1000 (`mkdir -p data backups && sudo chown 1000:1000 data backups`). With rootless podman, uncomment the `userns_mode: "keep-id"` line instead and use `podman compose`.

Then open `http://<host>:53530` and log in (HTTPS on 53443 once it's on in Settings → HTTPS).

All state lives in two bind mounts:

| Mount | Contents |
|---|---|
| `./data` → `/data` | `config.toml`, `liteblox.db` (accounts, nodes and their pinned SSH host keys, zones, publish log, audit log), `secret.key`, the zone history (`repo/`, git), drafts, and the certificate authority the agents trust (`pki/`) |
| `./backups` → `/backups` | node config backups. Point it at a NAS if you like |

Backing up LiteBlox itself means backing up `./data`.

### Accounts

Accounts are local to LiteBlox, with two roles that apply everywhere: `admin` (edit, publish, manage accounts) and `readonly` (view, diff, history). Admins manage accounts on the **Users** page, which also has the audit log; everyone changes their own password under **My account**. The CLI does the same:

```bash
liteblox user add <name> [--role admin|readonly]
liteblox user passwd <name>
liteblox user role <name> <role>
liteblox user del <name>
liteblox user list
```

Run these inside the container with `docker compose exec liteblox …`.

### Adding a node

Get the server ready first: **Help → Preparing a node** in the app (`/help/node-prep`, readable without logging in) covers the static IP, packages, setup account, firewall and a pre-flight checklist. Then, from the CLI or the **Nodes** page:

```bash
liteblox node add ns1 192.168.1.10          # shows the SSH host key fingerprint and pins it
liteblox node bootstrap ns1 --ssh-user admin  # installs the agent and takes over BIND (password prompt)
liteblox node primary ns1                   # ns1 holds every zone, the other nodes become its secondaries
```

Setup logs in once with temporary credentials (never stored). It snapshots `/etc/bind` to the backups folder, installs BIND if asked, makes `/etc/bind` and the zone files group-writable for `bind`, installs and starts the agent, checks it over mutual TLS, and takes over a server with the stock configuration. A server with a config of its own gets a **Take over** preview on its page instead: options, ACLs, keys and zones imported, `named-checkconf -px` equivalence shown, and blockers (views, for instance) listed. LiteBlox needs to reach TCP 8530 and 53 on each node.

### Editing and publishing

Open a zone from **Zones**. Edits on the record grid, the SOA card or the Raw tab go into a draft. **Review** shows the change summary, `named-checkzone` and the file diff, plus the state of every node serving the zone. **Publish**:

1. checks the primary is reachable and its file is still what LiteBlox last wrote there
2. bumps the serial past anything a node is serving
3. stages the new file on the primary, which runs its own `named-checkzone`
4. commits it to the zone history
5. switches the primary over, then checks the primary and each secondary answer with the new serial

**Reverse records** follow automatically: adding, changing or deleting an A/AAAA record also updates the PTR in the matching reverse zone, if LiteBlox has it, as a linked draft (static) or an update (dynamic). A PTR that already points elsewhere is never overwritten.

If the primary's file was edited by hand, publishing stops and Review shows the diff. You can either keep that edit (import it) or overwrite it.

**Many records at once** (4.1):

- **Select and act:** tick rows in the grid (the heading box selects every row the filter shows) to **Delete** them, **Set TTL** or **Set comment**, as one change to the draft, PTRs included.
- **Add many:** paste zone-file lines (`host1 A 192.0.2.10 ; printer`) or import a CSV (`name,ttl,type,value,comment`). The preview shows what each line adds, skips or gets wrong, and nothing is saved while any line has an error. **CSV** exports a zone in the same shape, and a CSV template comes with commented sample rows.
- **API batch:** `POST /api/v1/zones/{zone}/records/batch` takes up to 2000 adds, changes and deletes, all or none.
- **Move an address:** **Move to…** on Search's address card (or **Move…** on an IPAM address row) gives an address a new one everywhere: its A records in every static zone, its PTR, its DHCP reservation and its IPAM entry, previewed first, with the DNS side in linked drafts for one review and one publish.

### History

Every publish is a commit in the zone's history (**History** tab: who, when, the commit message given on Review, and the diff). Tick any two publishes or versions and **Compare** to see everything that changed between them. **Restore into a draft** on any version puts it back as a draft; publishing it gives it a new serial above anything the nodes serve. A restore doesn't touch PTR records in other zones.

### Dashboard and jobs

- **Dashboard:** tiles for nodes, zones, DHCP leases and time; **Needs attention**, a list of what's wrong with a link to the fix; a row per node with a pill for each service it runs, its DNS and DHCP roles coloured by health, time offset, last backup, load, memory, disk and a 24-hour graph of DNS queries; DHCP pool use with lease graphs; recent jobs and changes (scheduled jobs such as the IPAM sweeps only when they fail). It refreshes every minute, and the top bar's dot turns amber or red when something needs you. `GET /api/v1/status` gives the same for monitoring.
- The figures come from the health check: BIND's statistics channel (localhost only) and Kea's lease counts, read through the agent. They're kept per minute for two days, then as 15-minute averages for 30 days.
- **Jobs** (`/jobs`) lists every job across the nodes with filters; the **audit log** shows readable actions and hides sign-ins unless asked.

### Search

The top bar's search box (**/** jumps to it) looks through every zone's records, the DHCP reservations and leases, and the zones and subnets: by name or part of one, IP address, network or MAC. One address gets a card with its names, PTR, reservation and lease, what doesn't agree, and **Move to…** for admins. `GET /api/v1/search` gives the same.

### Zones, settings, keys and failover

- **Zones → Add zone**: forward lookup, reverse lookup (from a network such as `192.168.1.0/24`) or forwarding only (with `validate-except` for private domains). A zone's **Settings** tab adds and removes nodes, sets notify/also-notify/allow-transfer/allow-query, keeps the file sorted, switches **dynamic updates** on or off, and deletes the zone (its history is kept).
- **Dynamic zones**: grid edits apply at once as signed, guarded updates; client keys (**Settings → TSIG keys**, secret shown once) get per-zone grants such as `A AAAA DHCID` for DHCP or `TXT` on `_acme-challenge` names.
- **Stale DHCP names**: a name Kea registered stays behind when its removal is lost (the primary was down, say). A dynamic zone's **Stale names** lists those with no lease or reservation whose last lease ended longer ago than the reclaim time, to delete with their PTRs; the zone can also reclaim them hourly, holding back while DHCP isn't healthy or when more than a quarter would go at once.
- **Server settings** per node: recursion, forwarders, DNSSEC, allow-query/listen-on and extra statements, with copy-from-node, a review diff, a lockout guard and rollback. **Settings → ACLs** holds shared address lists.
- **Primary and failover**: **Make primary**, **Promote** (planned or with the old primary down), automatic demotion of a returning old primary with a report of records only it had, and config drift with Overwrite / Keep and a chooser for a hand-made second primary.

### DHCP

- **Set up DHCP** on a node's page installs Kea with a configuration that serves nothing. On the **DHCP** tab, tick the interfaces it answers on and add subnets (pools, router, DNS, domain, lease times, extra options as Kea JSON). Each subnet has an Overview (pool use and lease graphs), **Addresses** (live leases and reservations in one table: **Reserve** turns a lease into a reservation; deleting a lease removes its DNS name too) and Settings.
- **DNS registration:** a subnet can register clients in a dynamic zone (A + DHCID, and the PTR), signed with a client key; the review lists any grants the key still lacks. Kea's D2 sends the updates to the DNS primary and follows it on a promote. Or to **another DNS server** (its address and a TSIG key, with a **Test** that asks it for each zone signed with the key), or **off**.
- **Failover pair:** two nodes in hot-standby, talking over mutual TLS with certificates from LiteBlox's CA, on a link address you pick. The standby takes over within about a minute when the primary stops answering.

### IPAM

- **Networks and ranges:** add the networks you use (one click for each DHCP subnet and reverse zone not yet covered); a network inside another nests under it, so a `/16` per site holds its `/24`s. Name ranges in each (static, infrastructure, kept back); DHCP pools show up on their own.
- **A network's page:** a map of every address coloured by what uses it, a usage donut, and one table of every address, used and free, with its names, reservation, lease, MAC and vendor, a comment and any checks that don't agree. There's nothing to keep in sync: it's all read from the zones and Kea, and a comment edited there is written back to the record or reservation it came from.
- **Devices seen:** every minute each node's neighbour (ARP) table is read, so devices that talk to the servers show up with their vendor, first and last seen and earlier addresses; an address that keeps changing MAC is flagged in Needs attention. An optional per-network **sweep** pings every address hourly or daily to find quiet ones.
- **Devices:** label a MAC, or give it a name in DNS without fixing its address (a name-only reservation, in a subnet with DNS registration), then fix its address later.
- **Next free:** `POST /api/v1/ipam/next-free` (or `lbcli.py next`) finds addresses that are free on paper, checks them on the network with a ping and ARP from a node there, and holds them for a few minutes; blocks of up to 64 in a row too. `lbcli.py reserve 'k8s-{n}' --network … --blocksize 3 --group lab` names them in one go (A + PTR, or DHCP reservations with `--mac`), and `lbcli.py unassign --group lab` takes them away again.

### Tools and theme

- **Tools** in the top bar opens a **Subnet Reference** (/0 to /32: mask, usable hosts and where the next network starts) and a visual **Subnet Calculator** (divide and join a network, exclusions, a bookmarkable layout, copy as text), each in a new tab.
- The button by your username switches between **Auto** (follow the system), **Light** and **Dark**, remembered per browser.

### API

A JSON API under `/api/v1`, with a Swagger page at `/api/docs` for logged-in users. It reads nodes, zones, records, drafts, history, jobs and DHCP leases. It changes records, one at a time or up to 2000 in one batch (into a static zone's draft, then a publish job; a dynamic zone at once) and DHCP reservations (as jobs), deletes leases, and covers all of IPAM. `lbcli.py`, a single-file Python client (3.9+, nothing to install, downloadable from the token page), wraps next free, reserve, unassign and show. Calls need an API token: per user, read-only or full, made on the Users tab or My account (or `liteblox token add`), shown once and stored hashed. See **Help → The API**.

### Time (NTP)

**Set up time sync** on a node installs chrony (replacing systemd-timesyncd) with the sources on **Settings → Time**, one list for every node, written and checked like BIND's and Kea's configs. A node can also serve time to the networks you name, and keep doing so when its sources are unreachable. The DHCP subnet form suggests those nodes for clients' NTP option. Each node page shows chrony's source, stratum and offset; a node with no usable source is flagged.

### Backups

Each node's BIND files (`/etc/bind/**`, `/var/lib/bind/liteblox/` and any other zone files) is backed up through its agent into `/backups/<node>/`:

- **When:** daily at `backup_at` (default 03:15, container time), from **Back up now** on the node's Backups page or `liteblox backup run <node>|--all`, before every config change LiteBlox makes on a node, and over SSH just before bootstrap.
- **Skipped when unchanged:** a scheduled run writes nothing if no file changed since the last backup. It just records that it checked.
- **Retention:** everything from the last 24 hours, then the newest backup of each of the last 14 days and 8 weeks, plus 90 days of pre-change and pre-bootstrap snapshots. Failed attempts are listed with their error.
- **Restore** on a node (the same as a plain `/etc/bind` tarball, with owners and modes kept):
  ```bash
  tar zxf <node>-<timestamp>.tgz -C / && systemctl restart named
  ```
  The archive's manifest lands in `/var/lib/liteblox-agent/restored-backup/`.
- Key files are included by default, since a restore needs them. Each node's Backups page can exclude them. Downloading or viewing archive contents is admin-only.
- The Nodes list and the Dashboard flag a node with no successful backup in 48 hours.
- A DHCP node's backups also hold `/etc/kea` and the lease file.
- **LiteBlox itself:** back up `/data` (database, zone history, CA, session key). Without a copy, a fresh LiteBlox can **re-adopt** the nodes: it rebuilds its data from their generated config, and records it only if rendering it back gives every node's files byte for byte.

### Settings

`/data/config.toml` is created on first start. It holds only app settings, such as session lifetime, Secure cookies behind HTTPS, and backup schedule and retention. Nodes, zones, server settings, ACLs and keys are managed in the UI.

For HTTPS, either turn on LiteBlox's own under **Settings → HTTPS** (port 53443: a self-signed certificate, an imported one, or files your own Let's Encrypt tooling renews, picked up live; **HTTPS only** turns plain HTTP into a page saying so, and `liteblox https allow-http` undoes it), or serve LiteBlox behind a TLS reverse proxy and set `secure_cookies = true`. Set `FORWARDED_ALLOW_IPS` to the address the proxy's requests come from (for a proxy in a container on the same docker host, the docker network's gateway), so LiteBlox knows it's on HTTPS and logs client IPs correctly. The install help page has the details.

## Development

Requirements: Python ≥ 3.11, [uv](https://docs.astral.sh/uv/), podman. `named-checkzone`/`named-checkconf` (package `bind9-utils`) are needed for zone validation. They're already in the container image.

```bash
uv sync                                            # create .venv with app + dev deps
uv run pytest                                      # tests
LITEBLOX_DATA=./testenv/data LITEBLOX_BACKUPS=./testenv/backups \
    uv run liteblox serve --reload                 # dev server on :53530
LITEBLOX_DATA=./testenv/data uv run liteblox user add dev
```

`LITEBLOX_DEV_DHCP_NEVER_SERVE` is a development safeguard: a comma-separated list of networks (e.g. `192.168.1.0/24`) that Kea must never serve or listen on. LiteBlox refuses any DHCP change that would, at the review, the route and again right before the files leave for a node. Set it when a lab shares a network with a DHCP server that already works.

### Testing the container locally

```bash
./deploy/deploy.py --build                          # podman build → liteblox:<ver> (amd64), liteblox:<ver>-arm64, liteblox:latest
docker compose -f testenv/compose.yaml up -d        # runs the local image with testenv/data
testenv/reset.sh                                    # stop and wipe testenv state
```

End-to-end testing targets Debian 13 lab VMs (**lab-ns1**, **lab-ns2**) with a second NIC on an isolated bridge for DHCP, plus a DHCP client VM on that bridge, each with snapshots to roll back to. See [testenv/README.md](testenv/README.md).

## Releasing

The `deploy/` pipeline builds with podman for x86-64 and ARM64 (other architectures under `qemu-user-static`), pushes one multi-arch image as `:X.Y.Z`, `:X.Y`, `:X` and `:latest` to each `registry` line of `.publish` (`REGISTRY`, space-separated, overrides them; the logins are `podman login`'s), publishes the downloads (to the place in `.publish`; `PUBLISH_TO` overrides) and updates the website:

```bash
./deploy/deploy.py                  # archive → build → push → publish → site at the current VERSION
./deploy/deploy.py --bump-patch     # bump VERSION, prompt for a CHANGELOG entry, then all steps
./deploy/deploy.py --build          # build only
./deploy/deploy.py --site           # build and upload the website only
```

The website, [liteblox.dorkbrain.com](https://liteblox.dorkbrain.com), is generated by `website/build.py` from `website/content/`, the Help pages and `CHANGELOG.md`. Version, sizes and checksums come from the release files in `dist/`.

The source archive and one gzipped image tarball per architecture (`-amd64`, `-arm64`, both loading as `localhost/liteblox:<ver>`), each with a `.sha256.txt`, land in `dist/`. Then on the host that runs LiteBlox:

```bash
docker compose pull && docker compose up -d
```

## Roadmap

1. ✅ v1 (1.0): dual-master BIND: zone editor, drafts and review, two-phase publish, managed zones, automatic PTRs, history, node backups, accounts, built-in help
2. ✅ v2 (2.0): full BIND takeover (fresh and existing servers), primary/secondary, forwarding-only zones, server settings and ACLs, TSIG keys and dynamic zones, promote/demote, config drift
3. ✅ v3 (3.0): Kea DHCP (interfaces, subnets, pools, options, reservations, leases), DNS registration, a hot-standby failover pair, node clock checks, re-adopting the nodes after LiteBlox's data is lost
4. ✅ 3.1: a REST API with a Swagger page and per-user API tokens
5. ✅ 3.2: time sync with chrony on the nodes, and nodes serving time
6. ✅ 3.3: the Dashboard (status board, node and lease graphs), a Jobs page, readable audit log, DHCP leases and reservations in one table, and a consistency pass over every page
7. ✅ 3.3.1: static zones kept sorted (comment headings become zone notes), Kea reloading itself when its sockets fail, login throttling
8. ✅ 3.3.2: search across every zone and DHCP, with an address view that checks names, PTR, reservation and lease against each other
9. ✅ 3.3.3 / 3.3.4: fixes from moving a real network onto LiteBlox (DHCP subnets prepared before they're served, Windows clients registered in DNS, sortable Addresses)
10. ✅ 3.4: IPAM: networks and ranges, the used/free view, devices seen and flapping, MAC vendors, devices and name-only reservations, next free with holds, the IPAM API, `lbcli.py` and the sweep
11. ✅ 3.5: a Tools menu (subnet reference and a visual subnet calculator) and a light/dark switch
12. ✅ 4.0: **modular installs**: Settings → Modules (any mix of DNS, DHCP, time and IPAM), nodes without BIND and scanner nodes, IPAM records and PTR lookups, DHCP registering clients at another DNS server or not at all
13. ✅ 4.1: **bulk record edits**: select and act on a zone's rows, Add many from pasted lines or a CSV (with CSV export and a template), the API batch call, moving one address everywhere, stale DHCP names found and reclaimed on a schedule; the Dashboard's Services card with a pill per service

Next: nothing scheduled. Under consideration: BIND views (does a home or small office need them?) and ARP sniffing for IPAM (the sweep covers it for now).

## License

MIT: see [LICENSE](LICENSE). Copyright (c) 2026 Dorkbrain ([dorkbrain.com](https://dorkbrain.com)).

The Subnet Calculator is an altered version of [David C A Croft's Visual Subnet Calculator](https://github.com/davidc/subnets), Copyright (c) 2002, 2011, 2018, 2019 David C A Croft, under [its own license](liteblox/static/subnetcalc-LICENSE.txt). The vendored front-end libraries keep their licenses in [liteblox/static/vendor/](liteblox/static/vendor/).
