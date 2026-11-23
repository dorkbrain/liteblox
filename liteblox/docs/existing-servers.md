# Bringing in existing servers

A BIND server that already has zones and options of its own can be taken over too. LiteBlox imports its configuration, shows you exactly what it would write instead, proves that its version is equivalent, and only then switches the server over, so it keeps answering as before.

## 1. Prepare and set up the server

Go through [Preparing a node](/help/node-prep), steps 4–8 (time sync, packages, a setup account, firewall, the checklist). Leave your BIND configuration as it is.

Then **Nodes → Add node** and run **Set up**. Setup installs the agent and makes `/etc/bind` and your zone files group-writable for `bind`. Because the server has a configuration of its own, setup stops before taking it over and logs that you should review it on the node's page. Setup also takes a snapshot of `/etc/bind` before changing anything (on the node's **Backups** page).

## 2. Take over a server with its own config

On the node's page, **Take over** shows a preview:

| Section | What it shows |
|---|---|
| Equivalence | `named-checkconf -px` of LiteBlox's version against the server's, after normalizing statement order, `master`/`primary` and the zone files' new paths. It must match. |
| Server options | the options that become fields on the node's [Server settings](/help/server-settings), and anything else kept as written in its extra statements |
| ACLs, keys and other statements | ACLs and TSIG keys become LiteBlox's (shared by every node it takes over); other top-level statements (logging, statistics-channels…) are kept as written |
| Zones | each zone, whether it's new to LiteBlox or already there, and where its file moves (`/etc/bind/liteblox/db.<zone>`, or `/var/lib/bind/liteblox/dyn/` for a dynamic zone, listed with its grants). Forwarding zones come in as forwarding-only zones. |
| Files | the package's own files that stay included, and your configuration files that are retired into `/etc/bind/pre-liteblox/` |

**Take over** then backs the server up, writes the new configuration, checks over DNS that every zone still answers with the same serial, and rolls back if anything differs. Your zone files are copied to their new place; the originals stay where they were.

### What blocks a takeover

The preview lists anything LiteBlox can't represent yet. Nothing changes until you've dealt with it on the server and opened the preview again:

- **views**
- secondary zones, stub zones and zones with options LiteBlox doesn't write
- zones that take dynamic updates by address, ACL or rules other than key grants (key grants are imported: see [Dynamic zones on a server you take over](/help/dynamic#dynamic-zones-on-a-server-you-take-over))
- a `directory` other than `/var/cache/bind`, or statements with paths the agent doesn't allow
- an ACL, key or zone LiteBlox already has with different contents

## 3. Several servers with the same zones

Take over each server in turn. A zone LiteBlox already has from an earlier server is linked rather than imported again. If the copies differ (often just the serial), the zone's **Review** page shows the difference as a hand edit, and you choose which copy wins.

Then, on **Nodes**, **Make ns1 the primary**. Every other server becomes its secondary and transfers each zone from it, so from then on there's one copy to edit. See [Primary, failover and drift](/help/failover).

## An existing DHCP server

LiteBlox doesn't import a DHCP server's configuration (ISC dhcpd, an existing Kea, or a router's). **Set up DHCP** installs Kea with LiteBlox's own empty configuration, moving any Kea files the package brought to `/etc/kea/pre-liteblox/`. Then add the subnets, pools and reservations on the DHCP tab, and switch the old server off as you tick the interface ([DHCP (Kea)](/help/dhcp)). Clients keep their address until they renew, and a reservation pins one.
