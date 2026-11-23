# Quick start

From two fresh Debian servers to a forward zone (`example.com`) and its reverse zone (`0.168.192.in-addr.arpa`, for 192.168.0.0/24): ns1 is the primary and ns2 its secondary. It takes about half an hour. Every step below was run end to end on two Debian 13 servers.

This is the full setup, with all four [modules](/help/modules). Not running DNS on LiteBlox (DHCP only, or only an address list)? See [Getting started without DNS](/help/modules#getting-started-without-dns).

The examples use these addresses; substitute your own:

| | Address |
|---|---|
| ns1 (the primary) | 192.168.1.213 |
| ns2 (its secondary) | 192.168.1.214 |
| LiteBlox host | the machine running the container |

## 1. Prepare both servers

Follow [Preparing a node](/help/node-prep) on each server: static IP, `python3` and `sudo`, a setup account, and firewall openings. You don't configure BIND yourself; LiteBlox installs it if it's missing and writes its whole configuration.

Note each server's SSH host key fingerprint from the pre-flight checklist:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

## 2. Run LiteBlox

On the LiteBlox host, in an empty directory, save the project's `docker-compose.yaml` ([Installing](/help/install#run-it)) and start it:

```bash
mkdir -p data backups && sudo chown 1000:1000 data backups
docker compose up -d
docker compose ps           # liteblox shows "healthy" after its first health check, about 30 seconds
```

Everything LiteBlox keeps lives in `./data` (settings, database, zone history, certificates) and `./backups` (node backups). Back up those two folders and you've backed up LiteBlox.

## 3. Create the first admin

```bash
docker compose exec liteblox liteblox user add admin
```

Then open `http://LITEBLOX-HOST:53530` and log in. For anything beyond a home network, put LiteBlox behind a TLS reverse proxy and set `secure_cookies = true` in `./data/config.toml`.

## 4. Add and set up both servers

**Nodes → Add node**, name `ns1`, address `192.168.1.213` → **Read host key**.

LiteBlox shows the fingerprint it received. Compare it with the one from step 1 and confirm only if they match. LiteBlox pins the key and will refuse to connect if it ever changes.

You land on **Set up ns1**:

- **SSH user / password:** the setup account from step 1 (used for this run only, never stored)
- **Let LiteBlox manage the whole BIND config**: leave ticked
- **Make /etc/bind … group-writable:** leave ticked
- **Install BIND if it's missing:** leave ticked

**Run setup** shows a live log: it checks the server, installs BIND and the agent, then takes over the BIND configuration. It ends with `✓ LiteBlox now manages the whole BIND config on ns1` and `✓ Done`. The node's page shows it as **ready**, with **BIND config: managed by LiteBlox**.

Repeat for `ns2` at `192.168.1.214`.

> From the command line instead, with SSH keys rather than a password: `liteblox node bootstrap ns1 --ssh-user ADMIN --use-ssh-keys`, run wherever your keys are (see the [reference](/help/reference#nodes)).

## 5. Pick the primary

On **Nodes**, under **Primary and secondaries**, click **Make ns1 the primary**. ns2 becomes its secondary: from now on LiteBlox publishes to ns1, and ns2 copies every zone from it.

## 6. Create the forward zone

**Zones → Add zone**, **Forward lookup**:

- **Zone name:** `example.com`
- **Nameservers:** one per line; names inside the zone need their address:

        ns1.example.com 192.168.1.213
        ns2.example.com 192.168.1.214

- **Serve it on:** ns1 (the primary, always ticked) and ns2

**Add zone**. Each server is backed up, the zone is declared on both and checked over DNS. The log ends with:

```text
✓ ns1: serving example.com at serial 2026102401
✓ ns2: serving example.com at serial 2026102401 (transferred from the primary)
```

## 7. Create the reverse zone

**Zones → Add zone** again, this time **Reverse lookup**:

- **Network:** `192.168.0.0/24`. The form shows the zone name it becomes: `0.168.192.in-addr.arpa`.
- **Nameservers:** `ns1.example.com` and `ns2.example.com` (no addresses: they live in the other zone)
- **Responsible mailbox:** leave empty (for a reverse zone it defaults to `hostmaster.example.com.`, from the nameservers' domain)

## 8. Add hosts

Open **example.com**. **Add record** opens a row at the top of the grid:

| Name | Type | Value |
|---|---|---|
| `router` | A | `192.168.0.1` |
| `nas` | A | `192.168.0.10` |
| `printer` | A | `192.168.0.20` |
| `web` | A | `192.168.0.30` |
| `www` | CNAME | `web` |
| `@` | MX | priority `10`, mail server `web` |

For A and AAAA records, **sync PTR** is ticked by default. Each save adds the matching PTR to `0.168.192.in-addr.arpa`, and the grid confirms it (`added PTR 192.168.0.1 → router.example.com. in 0.168.192.in-addr.arpa`). The pending bar shows the changes are a draft that **publishes together with 0.168.192.in-addr.arpa**.

## 9. Review and publish

**Review** lists the six forward changes and, under **Also published**, the four PTRs, with `named-checkzone` results and the file diffs. Click **Publish example.com + 0.168.192.in-addr.arpa to ns1 (ns2 will transfer it)**:

- both zones get a new serial and are committed to the zone history
- ns1 checks and loads the new files
- ns2 is notified and transfers just the changes
- LiteBlox asks each server over DNS which serial it now serves

```text
✓ ns1 example.com: serving serial 2026102402
✓ ns2 example.com: serving serial 2026102402 (transferred)
✓ ns1 0.168.192.in-addr.arpa: serving serial 2026102402
✓ ns2 0.168.192.in-addr.arpa: serving serial 2026102402 (transferred)
```

## 10. Check it

From any machine allowed to query the servers:

```bash
dig @192.168.1.213 web.example.com +short          # 192.168.0.30
dig @192.168.1.214 www.example.com +short          # web.example.com. 192.168.0.30
dig @192.168.1.214 example.com MX +short           # 10 web.example.com.
dig @192.168.1.213 -x 192.168.0.10 +short          # nas.example.com.
dig @192.168.1.214 -x 192.168.0.20 +short          # printer.example.com.
```

Both servers give the same answers. If ns1 fails, ns2 keeps answering; **Promote** it on its page to make it the primary ([Primary, failover and drift](/help/failover)).

## 11. Optional: let DHCP register names

To have a DHCP server (or anything else that speaks DNS UPDATE) add hosts by itself:

1. On the reverse zone, **Settings → Dynamic updates → Switch on**. Do the same on a forward zone for DHCP clients; a zone of its own, such as `dhcp.example.com`, keeps them apart from your hand-made records.
2. **Settings → TSIG keys → Add a client key**, name `dhcp` → **Add key**, and download the key file (the secret is shown only once).
3. Grant it: on the `dhcp` key, the forward zone with types `A AAAA DHCID`, and `0.168.192.in-addr.arpa` with `PTR DHCID`.
4. Test from any machine with `nsupdate`, sending to the primary:

        nsupdate -k dhcp.key <<'EOF'
        server 192.168.1.213
        zone 0.168.192.in-addr.arpa
        update add 99.0.168.192.in-addr.arpa 300 PTR test.example.com.
        send
        EOF
        dig @192.168.1.214 -x 192.168.0.99 +short       # test.example.com.

See [Dynamic zones and TSIG keys](/help/dynamic) for the details.

## 12. Optional: DHCP with LiteBlox's Kea

LiteBlox can run Kea, the DHCP server, on the same two servers, and register its clients in the zone from step 11. Only one DHCP server should answer on a network, so turn off the old one (often the router) when you switch.

1. On each server's page, **Set up DHCP**: setup installs Kea with a configuration that serves nothing yet.
2. **DHCP → Servers**: on ns1, tick the interface on the network clients are on, **Review**, then **Serve on …**.
3. **DHCP → Add subnet**: `192.168.0.0/24`, a pool such as `192.168.0.100 - 192.168.0.199`, the router, and ns1 and ns2 as DNS servers.
4. To register clients: **DHCP → Settings → DNS registration → Key** `dhcp`; then on the subnet, **Register clients** in `dhcp.example.com`. The review lists any grants the key still needs, with **Add the missing grants**.
5. **DHCP → Failover pair**: ns1 primary, ns2 standby, each with its address on that network as the link. Open TCP 8001 between them first ([firewall](/help/node-prep)).

Every step shows the change to Kea's configuration and Kea's own check of it before anything is applied. A client that renews now gets its address from ns1, and its name appears in `dhcp.example.com`. See [DHCP (Kea)](/help/dhcp).

## 13. Backups

Each server already has backups: one taken over SSH before setup, and one before each configuration change (**Nodes → ns1 → Backups**). **Back up now** takes another. A daily backup runs at 03:15 and is skipped when nothing changed.

A backup is a plain tarball of the server's BIND configuration and zones (and Kea's configuration and leases), with owners and modes kept. To rebuild a server from one, install `bind9` and run:

```bash
tar zxf ns1-YYYYmmdd-HHMMSS-manual.tgz -C /
systemctl restart named
```

## What next

- **Day to day:** edit records in the grid, **Review**, **Publish**. Every publish is in the zone's **History**, and any version can be restored into a draft.
- **Server options** (recursion, forwarders, who may query): each node's **Server settings** ([Server settings and ACLs](/help/server-settings)).
- **Existing BIND servers:** [take them over](/help/existing-servers) with their zones and options.
- **If LiteBlox itself is lost:** keep a copy of its `./data` folder; without one, a new LiteBlox can [re-adopt the nodes](/help/backups#disaster-recovery).
