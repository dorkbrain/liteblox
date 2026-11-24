# Command line and settings reference

Run commands inside the container:

```bash
docker compose exec liteblox liteblox COMMAND …
```

## Accounts

| Command | Does |
|---|---|
| `liteblox user add NAME [--role admin\|readonly] [--password-stdin]` | create an account (admin by default); prompts for the password twice, or reads one line from stdin |
| `liteblox user passwd NAME [--password-stdin]` | set a new password |
| `liteblox user role NAME admin\|readonly` | change the role |
| `liteblox user del NAME` | delete the account |
| `liteblox user list` | accounts, roles, created and last login times |

Names are lowercase letters, digits, `_ . -` (up to 32); passwords need at least 8 characters. The last admin can't be demoted or deleted. A new password logs the account out of its other sessions. The **Users** page does the same in the browser.

## Nodes

| Command | Does |
|---|---|
| `liteblox node add NAME HOST [--ssh-port 22] [--agent-port 8530] [--yes] [--no-bind]` | read the node's SSH host key, show its fingerprint, and pin it after you confirm (`--yes` skips the question). `--no-bind`: a node without BIND (DHCP or Time only, or a [scanner](/help/modules#scanner-nodes)); always so with the DNS module off |
| `liteblox node bootstrap NAME --ssh-user USER [--use-ssh-keys] [--install-bind] [--no-fix-permissions] [--no-takeover] [--dhcp] [--radvd] [--ntp] [--no-bind \| --bind]` | set up (or repair/upgrade) the agent, then take over a server with the stock configuration. Prompts for the SSH password unless `--use-ssh-keys`, which uses the ssh-agent or `~/.ssh` keys of whoever runs the command. Unlike the web form, BIND is installed only with `--install-bind`. `--dhcp` also [sets up Kea](/help/dhcp#setting-up-dhcp-on-a-node), `--radvd` [radvd](/help/ipv6#router-advertisements-from-liteblox) for router advertisements, and `--ntp` [chrony](/help/ntp#setting-it-up-on-a-node) (a repair without them keeps each as it is). `--no-bind` / `--bind` change whether the node runs BIND for LiteBlox, while it serves no zones and isn't taken over (BIND itself isn't removed). |
| `liteblox node takeover NAME [--yes]` | print the [takeover](/help/existing-servers#2-take-over-a-server-with-its-own-config) preview, then take the node over after you confirm |
| `liteblox node readopt NAME... [--yes]` | after LiteBlox's own data was lost: print the [re-adopt](/help/backups#disaster-recovery) preview for these nodes, then rebuild LiteBlox's data from them after you confirm |
| `liteblox node settings NAME` | print the node's options as LiteBlox writes them |
| `liteblox node primary NAME [--yes]` | make the node the primary of every zone, the other taken-over nodes its secondaries (a promote when another node is the primary) |
| `liteblox node promote NAME [--yes]` | [promote](/help/failover#promote-moving-the-primary) a secondary in place of the current primary, which may be down |
| `liteblox node drift NAME` | show changes made to the node's generated configuration outside LiteBlox |
| `liteblox node overwrite NAME [--yes]` | write LiteBlox's configuration back over them |
| `liteblox node edit NAME [--host HOST] [--ssh-port N] [--agent-port N] [--dns-address IP] [--yes]` | read the SSH host key at the node's (new) address, show it next to the pinned one, and pin it after you confirm. With no options it only re-pins the key. A new address or agent port needs `node bootstrap` afterwards ([details](/help/troubleshooting#a-node-moved-to-a-new-address)). `--dns-address` sets the address other nodes use for transfers and NOTIFY (`''` = the node's address). |
| `liteblox node remove NAME [--yes]` | forget the node; nothing on the server changes ([details](/help/troubleshooting#removing-a-node)) |
| `liteblox node list` | nodes, status, agent and BIND versions |
| `liteblox node status NAME` | ask the agent for its status (JSON) |

## TSIG keys

| Command | Does |
|---|---|
| `liteblox key list` | keys and their grants (never the secrets) |
| `liteblox key add NAME [--algorithm hmac-sha256]` | create a client key and print its key file **once**; also `hmac-sha512`, `hmac-sha384`, `hmac-sha1` |
| `liteblox key grant NAME ZONE zonesub\|subdomain\|name [TYPES…] [--owner NAME]` | let the key update a zone (types default to `ANY`; `--owner` is the name for `subdomain` / `name`) |
| `liteblox key revoke GRANT-ID` | remove a grant (its number from `key list`) |
| `liteblox key delete NAME` | delete a client key and its grants |

See [Dynamic zones and TSIG keys](/help/dynamic#tsig-keys).

## API tokens

| Command | Does |
|---|---|
| `liteblox token add USER NAME [--read-only] [--expires DAYS]` | make an API token for a user and print it (the only time it's shown). Without `--read-only` it can do whatever the user's role allows. |
| `liteblox token list [USER]` | every token (or one user's): id, name, scope, its first characters, last use, expiry |
| `liteblox token revoke ID` | revoke a token at once |

Tokens are also managed on the **Users** tab (admins, for any user) and on **My account** (your own). The API itself is on the **API** page (`/api/docs`), for logged-in users. See [The API](/help/api) for what it does and curl examples.

## Backups

| Command | Does |
|---|---|
| `liteblox backup run NODE…` | back up those nodes now, then prune |
| `liteblox backup run --all [--kind scheduled]` | every set-up node; `--kind scheduled` skips nodes where nothing changed |
| `liteblox backup list NODE` | that node's backups |

## Other

| Command | Does |
|---|---|
| `liteblox modules` | which modules are on and what keeps each in use ([Modules](/help/modules)) |
| `liteblox modules --on dhcp ipam --off dns ntp` | switch modules on or off (switching off is refused while one is in use); `--save` alone keeps the current choice, so the Dashboard doesn't ask |
| `liteblox check` | version, folders, database schema, and whether `named-checkzone`, `named-checkconf` and `git` are available |
| `liteblox serve [--host 0.0.0.0] [--port 53530] [--https-port 53443] [--reload]` | run the web server (what the container does): plain HTTP on `--port`, and [HTTPS](/help/https) on `--https-port` while it's on; `--reload` restarts it on code changes, for development (HTTP only) |
| `liteblox healthcheck [--port 53530]` | exit 0 if the web server answers (used by the container healthcheck) |
| `liteblox --version` | version |

## HTTPS

| Command | Does |
|---|---|
| `liteblox https status` | on or off, the port, HTTPS only, the certificate and the last error (exits 1 on an error) |
| `liteblox https allow-http` | turn HTTPS only off: plain HTTP works again ([Getting back in](/help/https#getting-back-in)) |
| `liteblox https off` | turn HTTPS off, and HTTPS only with it |
| `liteblox https on [--name NAME …]` | turn HTTPS on; with no certificate yet, a self-signed one |
| `liteblox https regenerate [--name NAME …]` | a new self-signed certificate |

## config.toml

`./data/config.toml` (`/data/config.toml` in the container) is created on first start. Restart the container after editing.

| Setting | Default | Meaning |
|---|---|---|
| `[web] session_hours` | `12` | how long a login lasts |
| `[web] secure_cookies` | `false` | mark the plain-HTTP session cookie Secure; set `true` behind a reverse proxy's HTTPS (LiteBlox's own HTTPS always uses a Secure cookie) |
| `[backups] backup_at` | `"03:15"` | daily node backup time (HH:MM, container time zone); `""` turns scheduled backups off |
| `[backups] keep_daily` | `14` | days for which the newest backup is kept |
| `[backups] keep_weekly` | `8` | weeks for which the newest backup is kept |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `TZ` | (UTC) | time zone for `backup_at` and log times |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | reverse proxy addresses whose `X-Forwarded-*` headers are trusted |
| `LITEBLOX_DATA` | `/data` | data folder |
| `LITEBLOX_BACKUPS` | `/backups` | backups folder |
| `LITEBLOX_HTTPS_PORT` | `53443` | the port LiteBlox's own [HTTPS](/help/https) listens on in the container |

## Ports

| Port | Where | Used by |
|---|---|---|
| 53530/tcp | LiteBlox host | the web UI (plain HTTP) |
| 53443/tcp | LiteBlox host | the web UI over LiteBlox's own [HTTPS](/help/https), while it's on |
| 8530/tcp | each node | the agent (mutual TLS) |
| 22/tcp | each node | setup and agent upgrades |
| 53/udp+tcp | each node | DNS: clients, transfers and NOTIFY between nodes, and LiteBlox's serial checks, probes and dynamic-zone reads and updates |
| 67/udp | DHCP nodes, on the interfaces they serve | DHCP clients |
| 547/udp | DHCP nodes with an IPv6 subnet, on the interfaces they serve | DHCPv6 clients |
| 8001/tcp | the failover pair, on each node's link address | the two Kea servers (TLS both ways); the port can be changed |
| 8002/tcp | the failover pair, on each node's link address | the two kea-dhcp6 servers, once there's an IPv6 subnet; the port can be changed |
| 123/udp | nodes that serve time, from the networks they serve | NTP clients (and each node's own chrony, outbound, to its sources) |
| 53001/udp | each DHCP node, 127.0.0.1 only | kea-dhcp4 handing name registrations to its DDNS service (D2), which sends them to the DNS primary on 53 |

## Files on a node

| Path | What |
|---|---|
| `/etc/bind/named.conf` | written by LiteBlox: includes only the files below and the package's own root hints |
| `/etc/bind/liteblox/options.conf`, `top.conf` | the node's [server settings](/help/server-settings) |
| `/etc/bind/liteblox/acls.conf`, `keys.conf` | ACLs and TSIG keys (the same on every node; `keys.conf` is mode 0640) |
| `/etc/bind/liteblox/zones.conf` | every zone the node serves |
| `/etc/bind/liteblox/db.<zone>` | static zone files on the primary |
| `/var/lib/bind/liteblox/dyn/` | dynamic zone files and their journals, on the primary |
| `/var/lib/bind/liteblox/sec/` | secondaries' copies (plain text, readable) |
| `/var/lib/bind/liteblox/jnl/` | the primary's journals of static zones, for incremental transfers |
| `/etc/bind/pre-liteblox/<time>/` | the node's own configuration, moved aside at takeover |
| `/etc/kea/kea-dhcp4.conf`, `kea-dhcp6.conf`, `kea-dhcp-ddns.conf` | Kea's configuration, written by LiteBlox on a DHCP node (mode 0640; the last holds the DNS registration key) |
| `/etc/liteblox-radvd/radvd.conf` | the router advertisement config LiteBlox writes on a node with radvd; `liteblox-radvd.path` checks it and puts it in place as `/etc/radvd.conf`, running radvd only while it names an interface |
| `/etc/kea/tls/` | the failover link's certificate, key and the LiteBlox CA certificate |
| `/etc/kea/pre-liteblox/<time>/` | the Kea package's own configuration, moved aside at setup |
| `/var/lib/kea/kea-leases4.csv` | the leases (Kea's own file) |
| `/etc/systemd/system/liteblox-kea4-ctrl.*`, `liteblox-kea-ddns-ctrl.*` | the socket proxies that let the agent reach Kea's control sockets, under `/run/liteblox-kea/` |
| `/etc/chrony/chrony.conf` | chrony's configuration, written by LiteBlox on a node with time sync set up |
| `/etc/chrony/pre-liteblox/<time>/` | the chrony package's own configuration, kept at setup |
| `/etc/systemd/system/liteblox-chrony.path`, `liteblox-chrony.service` | restart chrony when LiteBlox writes its config |
| `/usr/local/lib/liteblox-agent/liteblox_agent.py` | the agent |
| `/etc/liteblox-agent/` | its config, certificate, key and the LiteBlox CA certificate |
| `/etc/systemd/system/liteblox-agent.service` | the service |
| `/var/lib/liteblox-agent/backups/` | the last 10 versions of each zone file the agent replaced, and the previous configuration of each change (for rollback) |
