# Security model

## Who can use LiteBlox

- Accounts are LiteBlox's own (not the servers' logins). Passwords are stored as argon2 hashes.
- **admin** can change everything, including accounts; **readonly** can look but not change, download backups or read their contents. Roles apply to the whole of LiteBlox, not per zone.
- Admins manage accounts on the **Users** page (or with the [command line](/help/reference#accounts)). Everyone changes their own password under **My account** (click your name at the top right), which asks for the current password first. LiteBlox won't demote or delete the last admin, and an admin can't delete their own account.
- Sessions are signed cookies (12 hours by default). Every form and every change request carries a per-session token, so another website can't make your browser change things.
- Deleting an account or changing its role takes effect on its very next request. Changing or resetting a password logs that account out everywhere else (your own change keeps the browser you made it in).
- Failed logins are throttled, counted over the last 15 minutes before the password is even checked:
    - **per account:** after 5 failures (counting only those since its last successful login)
    - **per address:** after 20 failures from one address, whatever names were tried

  Further attempts are refused with *Too many failed logins; try again in N minutes*, even with the right password, and the audit log records one **Refused a login** per lockout. Refused attempts don't count, so they can't extend it. The counts are kept in the database, so restarting LiteBlox doesn't reset them.
- This means someone else's wrong guesses can lock an admin out for **at most 15 minutes**. If you're locked out for real (a forgotten password), set a new one on the host: `docker compose exec liteblox liteblox user passwd NAME` (see [Locked out of LiteBlox](/help/troubleshooting#locked-out-of-liteblox)).
- Every change, login and failed login is recorded, with the client's address for logins; admins read it under **Users → Audit log**, filtered by user, action or detail. Sign-ins (logins, logouts, failed and refused logins) are hidden until you tick **sign-ins** or pick one of them as the action.
- LiteBlox serves plain HTTP on port 53530. Use its own [HTTPS](/help/https) on port 53443 (with **HTTPS only**, plain HTTP serves nothing but a page saying so), or put it behind a TLS reverse proxy and set `secure_cookies = true` (see [Installing](/help/install#https)). Its HTTPS certificate is not signed by the agents' certificate authority, so trusting one never means trusting the other.
- The Help pages, the login page and `/healthz` are readable without logging in. Nothing else is.

## How LiteBlox reaches the nodes

**Once, over SSH, for setup.**

- The node's SSH host key is shown to you and pinned when you add the node. LiteBlox refuses to connect if the key ever changes, until an admin checks the new key and [re-pins it](/help/troubleshooting#the-ssh-host-key-changed).
- The account and password you type for setup are held in memory for that one job. They're never written to the database, the job log or any file.

**Afterwards, only to the agent, over mutual TLS (TCP 8530).**

- LiteBlox runs its own small certificate authority (in `./data/pki`). Each agent gets a server certificate for its address. LiteBlox has a client certificate.
- The agent accepts only a client certificate from that CA with the name `liteblox`. LiteBlox accepts only agent certificates from the same CA, matching the node's address.
- The agent's config (`/etc/liteblox-agent/config.json`) can also list `allowed_ips`, to accept connections only from the LiteBlox host.
- BIND's statistics channel (query counts for the Dashboard) listens on `127.0.0.1:8053` and answers only the node itself. The agent reads it there; nothing on the network can.

## What the agent can do on a node

- It runs as the unprivileged `liteblox-agent` user in the `bind` group, under systemd sandboxing: no new privileges, the rest of the filesystem read-only (it may write only `/etc/bind`, `/var/lib/bind` and its own state), a private `/tmp`, no home directories, no capabilities.
- It **never runs sudo**, and never builds shell commands from what it receives.
- It writes only:
    - the generated configuration: `named.conf` and the files in `/etc/bind/liteblox/`. Each is checked against a strict allow-list for its kind (`acls.conf` holds only `acl` statements, `keys.conf` only keys, `zones.conf` only zones of the allowed types with their files in LiteBlox's own folders, and so on), and nowhere may it hold `include`, file paths outside BIND's folders or statements that load code
    - zone files in `/etc/bind/liteblox/` and `/var/lib/bind/liteblox/`, and static primary zone files BIND declares
    - at takeover, it moves the server's own configuration files into `/etc/bind/pre-liteblox/`
- It runs `named-checkzone`, `named-checkconf` and `rndc` (`reload`, `reconfig`, `refresh`, `status`, `zonestatus`), and reads `/etc/bind` and the zone files for backups.
- Every configuration it commits is checked with `named-checkconf` first, and it keeps the previous files so LiteBlox can roll a change back.
- **For IPAM** it reads the node's neighbour table (`ip -4 -s -j neigh`: the addresses and MACs the node has talked to) and, when asked, pings up to 64 addresses at a time, only on the networks the node is directly on, then reads the neighbour entries the pings left. It uses an unprivileged ping socket, which Debian allows every user, so it needs no extra capabilities and can't send anything but echo requests.

**On a node with Kea (DHCP):**

- Setup adds the agent to the `_kea` group, so it may also write `/etc/kea`. It writes only Kea's two config files and the failover pair's certificate files in `/etc/kea/tls/`.
- Each config file is checked against an allow-list:
    - the hook libraries are only `lease_cmds` and `ha`, from the package's own folder
    - control sockets, the lease file and logging go to fixed places
    - a failover pair is hot-standby with exactly two peers, its certificate paths fixed
    - nothing loads other code or writes elsewhere
- Kea checks each file itself too (`kea-dhcp4 -t`), and the previous files are kept for rollback.
- Kea makes its control sockets reachable by its own user only. Two small socket proxies, running as `_kea`, offer them to the agent's group alone, and nothing listens on the network for commands. The agent sends only the commands LiteBlox uses (status, config reload, reading and deleting leases, the failover pair's own).
- The failover link between two nodes is TLS in both directions, with certificates from LiteBlox's CA for each node's link address: each server accepts only its partner.

**On a node with time sync (chrony):** setup makes `/etc/chrony` writable for the agent's group. The agent writes only `chrony.conf`, checked against an allow-list:
- sources by name or address
- the networks it serves
- the fixed lines Debian ships, with fixed paths

There's nothing that includes other files, reads keys from elsewhere, or adds reference clocks. chrony checks the file too (`chronyd -p`). The agent can't restart chrony itself: a systemd path unit does that when the file changes.

**Upgrading the agent without SSH:** the agent can't replace its own code: `/usr/local/lib/liteblox-agent` is root's, and the sandbox keeps it read-only. When LiteBlox sends a new agent (over mutual TLS, from an admin's **Upgrade agent**), the agent saves it in its own state folder and restarts. Before it starts, systemd runs a small installer as root (`ExecStartPre=+`), which the agent can't change either:
- it reads the saved file without following links, and only a regular file the agent user owns, up to 2 MB
- the file must match the checksum LiteBlox sent, parse as Python (it's never run by the installer) and be a LiteBlox agent, and must not be older than the installed agent
- it keeps the old agent and puts it back if the new one doesn't start twice in a row
- it writes only the agent and its own small files, in root's folder

The new agent then runs exactly as before: unprivileged and sandboxed. So an attacker who controlled the agent could at most make their foothold survive a restart, with no more access than the agent already has. The unit, the installer, the config and the certificates change only by Repair over SSH.

## The trade-off on the node

For the agent to write zone files without sudo, setup makes `/etc/bind` and the zone files **group-writable for `bind`**. Anything running as group `bind`, which includes `named` itself, can then replace files in `/etc/bind`. Untick the option during setup if you'd rather manage those permissions yourself; LiteBlox then can't write zones it can't reach, and the node's page shows which.

## Secrets at rest

| Where | What | Protection |
|---|---|---|
| `./data/liteblox.db` | accounts (password hashes), nodes, zones, **TSIG key secrets**, the failover pair's private keys | owner-only |
| `./data/secret.key` | session signing key | owner-only |
| `./data/pki/` | the CA and LiteBlox's client key | owner-only folder |
| `./backups/` | node backups, **including BIND keys** by default | files owner-only |
| node: `/etc/liteblox-agent/agent.key` | the agent's private key | root + `liteblox-agent` only |
| node: `/etc/bind/liteblox/keys.conf` | every TSIG key LiteBlox writes | mode 0640, group `bind` |
| node: `/etc/kea/kea-dhcp-ddns.conf` | the TSIG key DHCP registers names with | mode 0640, group `_kea` |
| node: `/etc/kea/tls/ha.key` | the failover link's private key | mode 0640, group `_kea` |

Anyone with `./data` can impersonate LiteBlox to the agents and sign updates to every dynamic zone. Back it up somewhere as safe as the servers themselves.

A client key's secret is shown once, to the admin who created or replaced it, and is never shown in the key list, logs or configuration views (LiteBlox masks `secret` in every configuration it displays).

## API tokens

- A token is shown once; LiteBlox keeps only a SHA-256 hash of it (it's random and long, so a plain hash is enough), plus its first characters to tell tokens apart.
- The API takes only tokens (`Authorization: Bearer`), never the login session, so a page in your browser can't be made to call it. A token doesn't log anyone into the pages either.
- A token is **read only** or **full**. Full means what its user may do, checked again on every call. A role change or a deleted user applies at once.
- Changing a password doesn't revoke tokens. Revoke them on the Users tab or My account. An expiry is optional, and each token's last use (when, from which address) is listed.
- Every change made with a token is in the audit log under its user, with the token's name.

## Not (yet) included

- no lockout beyond the 15-minute throttle (still, don't expose LiteBlox to the internet)
- no two-factor login
