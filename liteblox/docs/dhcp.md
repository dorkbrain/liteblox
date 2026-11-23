# DHCP (Kea)

LiteBlox runs **ISC Kea** as the DHCP server on its nodes, alongside BIND. A node can run both: DNS for everyone, and DHCP on the network interfaces you pick.

LiteBlox serves DHCPv4 subnets from one node, or from two nodes as a [failover pair](#a-failover-pair), with reservations, a leases view and DNS registration.

## What LiteBlox runs

| Piece | What it does |
|---|---|
| `kea-dhcp4` | the DHCPv4 server; its leases are kept in a file on the node (`/var/lib/kea/kea-leases4.csv`) |
| `kea-dhcp-ddns` (D2) | registers clients' names in your dynamic zones, sending its updates to the DNS primary ([details](#registering-clients-in-dns)) |
| `liteblox-kea4-ctrl` / `liteblox-kea-ddns-ctrl` | two small systemd socket proxies that let the agent send commands to Kea (see below) |

There's no `kea-ctrl-agent` and no database server. LiteBlox writes `/etc/kea/kea-dhcp4.conf` and `/etc/kea/kea-dhcp-ddns.conf` itself, the same way it writes BIND's configuration.

## Setting up DHCP on a node

On the node's page, the **DHCP (Kea)** card has **Set up DHCP**. It opens the **Repair / upgrade agent** form with **Set up Kea DHCP** ticked; the CLI equivalent is `liteblox node bootstrap NAME --dhcp`. Over SSH, setup:

1. masks Kea's services, then installs `kea-dhcp4-server kea-dhcp-ddns-server`, so Debian's sample configuration never runs
2. moves the package's own config files to `/etc/kea/pre-liteblox/<time>/`
3. writes LiteBlox's configuration (no interfaces, no subnets), checks it with `kea-dhcp4 -t`, and starts both services
4. adds the `liteblox-agent` user to the `_kea` group, makes `/etc/kea` group-writable (setgid `_kea`, so every file there stays readable for Kea), and installs the two socket proxies

Running setup again checks all this and keeps the configuration LiteBlox wrote. **Repair / upgrade agent** without the box ticked keeps the agent's access to Kea on a node that already has it.

**Why the socket proxies:** Kea 2.6.3 creates its control sockets so that only its own `_kea` user may connect (a security fix). Each proxy runs as `_kea` and offers the same socket under `/run/liteblox-kea/`, where only the agent's group can connect.

## Choosing where Kea answers

On the **DHCP** tab, **Servers** lists each node that runs Kea, with its failover role and the interfaces it serves. **Change interfaces** under a node opens its network interfaces and their addresses; the one LiteBlox reaches the node through is marked *management*.

- Tick the interfaces Kea should answer DHCP on, then **Review**.
- The review shows the change to Kea's configuration and Kea's own check of it on the node (`kea-dhcp4 -t`). **Serve on …** applies it.

Kea answers nothing on an interface you don't tick, even if a subnet is on its network. If an interface isn't up when Kea starts (at boot, say), Kea tries it again every 5 seconds for 10 minutes; the node's DHCP card and the Dashboard show **not listening** until it can. If it still can't after that, Kea stops trying by itself, so the health check reloads it as soon as the node reports all of Kea's interfaces up (at most every 10 minutes). A Kea config changed on the node is left alone, because the reload would undo it.

**One node serves, or a pair.** Two independent Kea servers handing out the same pool would give the same address to two clients, so a second node serves only as the standby of a [failover pair](#a-failover-pair).

**Before you tick an interface,** make sure no other DHCP server answers on that network (often the router), or turn that one off at the same moment. Two servers on one network give clients conflicting answers. To take over from one, prepare everything first and tick the interface last: see [Moving DHCP over from your router](#moving-dhcp-over-from-your-router).

**Unticking an interface** stops Kea answering there, but keeps its subnets and reservations: they're **not served** until you tick it again.

## Subnets and pools

**Add subnet** on the DHCP tab. Once it exists, the subnet's page has three tabs:

- **Overview:** how full the pools are, graphs of active leases over the last day and week, which nodes serve it, its options (marked when they come from DHCP → Settings), lease time and DNS names. It's built from what the health check records each minute, so it doesn't ask Kea.
- **Addresses:** its leases and reservations in one table (see [Leases and reservations](#leases-and-reservations)).
- **Settings:** the fields below, and **Delete** in the danger zone at the bottom.

The fields:

| Field | Meaning |
|---|---|
| **Subnet** | the network, e.g. `192.168.0.0/24`. A node running Kea needs an address in it; Kea answers for the subnet on that interface only. If the interface isn't ticked yet, the subnet is saved **not served**: Kea's configuration doesn't change, and Kea answers for it once you tick the interface. |
| **Pools** | the addresses Kea hands out, one range per line (`192.168.0.100 - 192.168.0.199`) or a CIDR. Pools can't include the network or broadcast address, the router, or the server's own address. Keep them clear of addresses you give out by hand. |

Each subnet gets a number (Kea's `subnet-id`) that's never reused, so Kea never mixes an old subnet's leases into a new one.

### Options

| Field | Kea option | Notes |
|---|---|---|
| Router | `routers` | the default gateway |
| DNS servers | `domain-name-servers` | the subnet form suggests LiteBlox's DNS nodes with an address in the subnet |
| Domain | `domain-name` | the domain clients add to short names |
| Search domains | `domain-search` | |
| NTP servers | `ntp-servers` | the subnet form suggests LiteBlox's [time servers](/help/ntp#serving-time) with an address in the subnet |

**DHCP → Settings** holds the same options for every subnet; a subnet's own value wins. Anything else goes in **Extra options**, as Kea's JSON list (`[{"name": "time-offset", "data": "3600"}]`). **Extra subnet settings** takes other Kea `subnet4` parameters as a JSON object. Kea checks both on the node before anything changes.

### Lease times

**Lease time** (`valid-lifetime`), **Renew after** and **Rebind after** are in seconds. Empty uses DHCP → Settings, then Kea's default (a lease of 7200 seconds; clients renew at half of it).

**Authoritative** (Settings): Kea answers a client asking for an address that isn't valid on that network with a NAK, so the client starts over at once. Turn it on when Kea is the only DHCP server on its networks.

## Reservations

A reservation always gives one client the same address. On the subnet's page, **Add reservation** (or **Reserve** on a lease, which fills it in):

| Field | Meaning |
|---|---|
| **MAC address** | the client's network card. `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` and `aabb.ccdd.eeff` all work. |
| **IP address** | in the subnet, but not its network or broadcast address, the router, or the DHCP server itself. Inside a pool is fine: Kea keeps a reserved address for its client and doesn't lease it to anyone else (if another client holds it at that moment, the reserved client gets it once that lease ends). |
| **Hostname** | optional: the name the client gets, and the one it's registered under in DNS when the subnet registers clients. Empty: the client's own name. |
| **Options** | a router, DNS servers, domain or NTP servers just for this client |

Like every DHCP change, it's reviewed first (with a warning if another client holds the address right now) and applied as a job.

A client already holding another address keeps it until it renews; Kea then moves it to the reserved one. To move it at once, delete its lease (below) and let it ask again.

### Name-only reservations

In a subnet that [registers clients in DNS](#registering-clients-in-dns), a reservation can leave **IP address** empty and give a **Hostname**. The client then gets any address from the pool, as before, but is always registered in DNS under that name, whatever name it sends itself. It's the easy way to give a phone or a laptop a name you choose without picking an address for it.

The Addresses tab shows it as **named, online** on its lease's address, or **named, offline** (address *any*) while it has no lease. Its client keeps the name it registered until its lease renews or ends. [IPAM's device page](/help/ipam#devices) takes a device up a step (a name, then a fixed address) and back down.

## Leases and reservations

A subnet's **Addresses** tab lists every address that has a lease or a reservation, by address: the client's MAC, its name (linked to its DNS record when it's registered), its state, and when its lease ends. **DHCP → Leases** shows the same for every subnet on one page. The filter box narrows the list as you type (an address, a MAC, a name or a state). Click a column's heading to sort by it (again to reverse); the list starts in address order. The heading counts the active leases, any declined or ended ones, and the reservations.

| State | Meaning |
|---|---|
| *leased* | a client holds a lease from a pool |
| *leased outside the pools* | a lease on an address outside every pool (usually a reservation since removed) |
| *reserved, online* | a reservation, and its client holds the address now |
| *reserved, offline* | a reservation whose client holds no lease right now |
| *reserved, held by another client* | another client got the address before the reservation; the reserved client gets it once that lease ends (or delete it) |
| *declined* | a client said the address was already in use (another device has it, often one with a static address), so Kea holds it back for a while. It has no MAC. The Dashboard counts it as taken in the pool. |
| *expired-reclaimed*, *released* | a lease Kea keeps a record of but doesn't count as in use |

- **Reserve** (on a lease) opens a new reservation filled in from it, keeping the address the client has now: the quickest way to pin a device you've just seen.
- **Edit reservation** opens the reservation.
- **Delete lease** removes the lease at once, along with the DNS name and PTR Kea registered for it. The client gets a new lease (and name) when it next asks.

**Export CSV** (on the Addresses tab, and on DHCP → Leases for every subnet) downloads the table, read from Kea again, with the columns `subnet,ip,state,mac,hostname,reserved,lease_state,expires,node,in_pool,dns_zone`: `reserved` is `address` or `name only`, `expires` is in LiteBlox's local time, and `dns_zone` is the zone the client's name was registered in. A node that couldn't be read gets a `#` line at the top, and the file holds what the others had. A client picks its own hostname, so a cell that would start a spreadsheet formula (`=`, `+`, `-` or `@` first) gets a `'` in front.

LiteBlox reads leases live from Kea and keeps no copy; Kea's own lease file (`/var/lib/kea/kea-leases4.csv`) is in each node's backups.

## A failover pair

Two nodes can share DHCP as a **hot-standby pair**:
- the **primary** answers every client
- the **standby** keeps a copy of every lease as it's handed out, and takes over when the primary stops answering

Clients notice nothing beyond their next renewal going to the other server.

**Setting it up:**
1. Set DHCP up on both nodes (each node's page → **Set up DHCP**). The standby needs an interface with an address on each network the primary serves. LiteBlox matches them **by network**, so their names may differ (a Raspberry Pi's VLAN interface `eth0.100` beside a VM's `ens19`, say): the review says which of the standby's interfaces stands in for which of the primary's, and so does **Servers** afterwards.
2. On the DHCP tab, **Failover pair**: pick the primary and the standby, and each one's **link address**, which is where it listens for its partner. An address on the DHCP network is a good choice. Open TCP **8001** (or the port you pick) between the two addresses.
3. **Review**, then **Pair them**. The standby changes first, then the primary. LiteBlox waits until both report **hot-standby**; if they don't find each other within 90 seconds, both are rolled back.

**The link is TLS both ways.** LiteBlox's own CA issues each node a certificate for its link address. Each server accepts only its partner, so leases (MACs and names) never cross the network in clear.

**When a node dies:**
1. Within about a minute (no heartbeat, and clients going unanswered), the other one goes to **partner-down** and serves on its own. The Nodes page flags it.
2. When the node comes back, it first copies the leases it missed from its partner (**syncing**).
3. Then both return to **hot-standby**, and the primary serves again.

DNS registration works throughout: whichever server answers sends the updates.

**Clocks:** the two must agree within a minute, or Kea stops failover altogether (**terminated**). LiteBlox [checks the clocks](/help/troubleshooting#a-nodes-clock-is-off) every minute.

**Changes** on the DHCP tab (subnets, reservations, settings) go to both nodes, the standby first. The standby's interfaces follow the primary's: **Change interfaces** on the primary matches the standby's again, and is refused if the standby has nothing on one of the networks or can't be reached. Subnets always name the primary's interface; the standby's own Kea configuration uses its own names.

**End the pair** keeps one node serving and stops DHCP on the other.

## Registering clients in DNS

A subnet can register each client in DNS:
- **forward:** an A record (`host.SUFFIX`), plus a DHCID record that marks the name as DHCP's
- **reverse:** a PTR in the reverse zone that covers the subnet, if there is one

Kea's DDNS service (D2) on the DHCP node sends these as signed updates (RFC 2136). When the lease is released or expires, it removes them.

**Where they go:** **DHCP → Settings → DNS registration** has three choices:
- **LiteBlox's DNS:** a dynamic zone on LiteBlox's own nodes; updates go to the DNS primary and follow it. Only offered while the [DNS module](/help/modules) is on. Set up as below.
- **Another DNS server:** a DNS server LiteBlox doesn't run (an Active Directory DNS, a BIND or a router you keep). See [Registering at another DNS server](#registering-at-another-dns-server).
- **Off:** nothing is registered; the **Register clients** box on each subnet keeps its tick for later.

Switching between them keeps what you set for the others. The review lists the subnets that stop registering, or that have nowhere to register yet.

**Setting it up in LiteBlox's DNS:**
1. The zone must be [dynamic](/help/dynamic). A subdomain just for DHCP clients (`dhcp.home.lab`) keeps their names apart from the ones you manage, but the zone itself works too.
2. **DHCP → Settings → DNS registration → Key**: the TSIG key Kea signs with. Make a key for DHCP on **Settings → TSIG keys**.
3. On the subnet, under **DNS registration**: tick **Register clients**, pick the **Zone**, and optionally a **Name suffix** inside it.
4. **Review** shows where names go, which reverse zone gets the PTRs, and where updates are sent. If the key isn't yet allowed to update those names (`A AAAA DHCID` in the forward zone, `PTR DHCID` in the reverse one), the review lists the missing grants. **Add the missing grants** adds them right there (the job's log shows under the button, since each grant rewrites BIND on the nodes), then reviews the form again, so you can apply.

**When names are updated:** at every new lease and every renewal, so a client that moves to another address (onto its reservation, say) has its name follow at once. It's one small update per client renewal.

**Clients that want to update their own name:** a client may ask to add its own A record (Windows does, with DHCP option 81). Kea would leave that to the client, which can't update your zone, so only the PTR would appear. LiteBlox tells Kea to register the name anyway (`ddns-override-client-update`), so every client gets both.

**Names Kea won't touch:** before it adds a name, Kea checks it isn't already there without its DHCID. A name you created by hand (or another client's) is left alone, and that client simply doesn't get registered. The client's own hostname is used; characters a DNS name can't have become `-`.

**After a promote:** D2 follows the primary by itself. Promote, Make primary, a returning node brought in line, and a change of the primary's DNS address all rewrite D2's configuration. A DHCP node that's down at the time catches up when the health check next sees it.

While a subnet registers in a zone, that zone can't be switched off dynamic or deleted, and the key can't be deleted. Replacing the key's secret updates Kea too.

A name whose removal was lost stays in the zone; a dynamic zone's **Stale names** finds such names, and the zone can reclaim them on a schedule: see [Stale DHCP names](/help/dynamic#stale-dhcp-names).

### Registering at another DNS server

For a DNS server LiteBlox doesn't manage. It must accept signed dynamic updates for the zones clients go in.

1. On that server: a TSIG key for Kea, allowed to update `A AAAA DHCID` names in the forward zone and `PTR DHCID` in the reverse zone (in BIND: `update-policy { grant kea-key zonesub ANY; };`).
2. **DHCP → Settings → DNS registration → Another DNS server**: its **IPv4 address** (the primary of those zones: Kea sends updates there, not to a secondary), the **port** (53), and the key's **name**, **algorithm** and **secret** (from the key file: `secret "…";`). The secret is never shown again; leave it empty to keep the saved one.
3. On each subnet, under **DNS registration**: tick **Register clients** and give the **Domain** clients are registered in (`dhcp.home.lan`: a zone on that server). **Reverse zones** is optional: left empty, the PTRs go in the zone for the subnet's /24 (a /22 gets its four /24 zones; a /16 its /16 zone). Give them (`…in-addr.arpa` zones that each cover part of the subnet, separated by spaces) when that server's reverse zones are cut differently.
4. **Test** (on DHCP → Settings, and in each subnet's review) asks the server for each zone's SOA, signed with the key, the way Kea will send its updates. It shows whether the server answers, knows the key and its secret (BADKEY, BADSIG), holds the zone itself, and whether the clocks agree (BADTIME). Whether the key is allowed to update the names is the server's policy, which can't be checked from here: watch the first lease's names appear.

LiteBlox doesn't read that server's zones: search and IPAM show the names Kea registered only through IPAM's [PTR lookups](/help/ipam#ptr-lookups-rdns) (point them at the same server), and the lease's hostname.

## Moving DHCP over from your router

A subnet that isn't served yet can be set up completely, reservations and all, without Kea answering anyone. So the switch from another DHCP server (a router, OPNsense, pfSense) takes one change:

1. **Days ahead:** lower the old server's lease time (to an hour, say), so clients ask again soon after the switch, and soon again if you go back.
2. **Prepare in LiteBlox:** set DHCP up on the nodes, fill in **DHCP → Settings** (the router, DNS servers, domain and lease time the old server hands out), pair the nodes if you have two, and **Add subnet** with its pool. The review says it's saved but not served. Add the reservations; through the [API](/help/api) they can be copied from the old server's export. Each of these is saved without touching Kea, so they're quick.
3. **Switch:** turn the old server's DHCP off, then **Change interfaces** on the serving node (the primary, in a pair): tick the interface. The review lists what Kea starts answering for. Apply it. Clients that renew get no answer from the old server and move to Kea; each one asks for the address it had, and a reserved device gets its reservation.
4. **Check:** from a client, `sudo nmap --script broadcast-dhcp-discover` shows one server offering. New leases appear on the subnet's Addresses tab.

**To go back:** untick the interface (Kea stops answering; the subnet stays, not served), then turn the old server back on. Clients move back as their leases come up for renewal.

## Review, apply and roll back

Every change on the DHCP tab is reviewed first: the change to each node's Kea configuration, and Kea's own check of it on the node. Then a job applies it, node by node:

1. LiteBlox backs the node up.
2. The agent writes the new files, and Kea reloads them. If Kea refuses them, the agent puts the old files back.
3. LiteBlox checks that both Kea services answer and that kea-dhcp4 has its network sockets open.

If any step fails, every node the job changed is rolled back, and so is the change on the DHCP tab.

A node whose configuration the change leaves as it is (a subnet that isn't served yet, a reservation in one) isn't touched: the job says *unchanged: nothing written*, Kea isn't reloaded, and a failover pair doesn't have to find each other again. **Rewrite DHCP config** on a node always writes.

## The DHCP card

| Line | Meaning |
|---|---|
| **Kea** | the installed version |
| **kea-dhcp4**, **DDNS (D2)** | *running* with its process id, uptime and when it last loaded its config, or *not answering* with the error |
| **Serving** | the interfaces Kea answers DHCP on, and the subnets on each |
| **Interfaces** | the node's network interfaces and addresses. The one LiteBlox reaches the node through is marked *management*. |

**Rewrite DHCP config** writes LiteBlox's configuration again: the node is backed up first, the agent checks the files with `kea-dhcp4 -t`, and Kea reloads them. If Kea refuses them, the agent puts the previous files back. If Kea stops answering afterwards, LiteBlox rolls the change back.

## On the Dashboard

The Dashboard's **DHCP leases** tile and **DHCP pools** card show how full each pool is, with a graph of the last day: the health check reads the leases from the failover primary each minute (from the standby when the primary doesn't answer). Leases on reserved addresses outside the pools are counted apart. Its **Needs attention** list shows the failover state when it isn't hot-standby, a Kea config changed on a node, and a node whose DHCP config is behind (it missed a change while unreachable; the health check writes it again). See [The Dashboard](/help/dashboard#dhcp-pools).

## Changes made on the node

Every minute the health check compares Kea's config files with what LiteBlox wrote. If one was edited on the node, the card shows **changed outside LiteBlox** with the differences (TSIG secrets masked), and **Overwrite the changes** writes LiteBlox's version back. There's no "keep": LiteBlox doesn't read Kea's configuration back in.

## Backups

A node's [backups](/help/backups) include `/etc/kea` and the lease file. `kea-dhcp-ddns.conf` holds TSIG secrets, so a backup without keys leaves it out.
