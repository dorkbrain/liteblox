# IPv6

LiteBlox has always handled IPv6 in DNS: AAAA records, `ip6.arpa` reverse zones, PTRs that follow AAAA edits, and BIND listening on IPv6 (`listen-on-v6` in [server settings](/help/server-settings)). From 6.0 it also runs **DHCPv6** with Kea, alongside DHCPv4 on the same nodes.

## What LiteBlox does for IPv6

| Piece | IPv6 |
|---|---|
| DNS | AAAA records, `ip6.arpa` zones (a prefix that's a multiple of 4), PTRs, AAAA glue |
| DHCP | DHCPv6 subnets with address pools and [delegated prefixes](#delegated-prefixes), [reservations by DUID or MAC](#reservations-duid-or-mac), leases, [DNS registration](#registering-clients-in-dns) (AAAA + PTR), the [failover pair](#the-failover-pair) |
| NTP | nodes [serve time](/help/ntp#serving-time) to IPv6 prefixes; DHCPv6 hands them out (`sntp-servers`) |
| IPAM | [IPv6 networks](/help/ipam#ipv6-networks): the addresses LiteBlox knows of (AAAA, DHCPv6, IPAM records, NDP), Check by ICMPv6, Add DNS (AAAA + PTR) |
| Search | IPv6 addresses and prefixes, DUIDs, delegated prefixes, `ip6.arpa` zones |
| API, lbcli, CSV | [`/api/v1/dhcp6`](/help/api#dhcpv6) (subnets, leases, reservations), IPv6 in IPAM's calls and in Search's; `lbcli.py show` an IPv6 address; CSV of a DHCPv6 subnet's addresses, of every DHCPv6 lease, and of an IPv6 network's addresses |
| Router advertisements | sent by your router ([what to set](#router-advertisements)), or by LiteBlox's nodes for a subnet that asks ([details](#router-advertisements-from-liteblox)) |

## Router advertisements

An IPv6 client doesn't look for a DHCP server on its own: it waits for a **router advertisement** (RA) from the router on its link, and the RA's flags tell it what to do:

| Flag | Meaning |
|---|---|
| **M** (managed) | get an address from DHCPv6 |
| **O** (other) | get options (DNS servers, search domains) from DHCPv6 |
| **A** on the prefix (autonomous) | make an address yourself from the prefix (SLAAC) |

The RA also carries the **default route** and the **prefix**: DHCPv6 has no router or subnet-mask option. A DHCPv6 address arrives as a single address (a /128), and only the RA's prefix tells the client the rest of the /64 is on its link. Without any RA, a client that got a DHCPv6 address by hand (`dhclient -6`) can't reach its neighbours, and most clients don't ask DHCPv6 at all.

**What to set on your router:**
- **DHCPv6 only** (every address from LiteBlox, so every client has a lease and a name): **M** and **O** on, the prefix with **A off**.
- **DHCPv6 and SLAAC**: **M** and **O** on, **A on**. Clients may take both kinds of address.
- **SLAAC with DNS from DHCPv6**: **O** on, **M** off, **A on**: a subnet with no pools hands out options only.

**Android doesn't do DHCPv6 addresses:** it only uses SLAAC. On a network with Android devices, leave **A** on, or they get no IPv6 address at all.

By default LiteBlox sends no router advertisements: in a real network the router already does.

## Router advertisements from LiteBlox

For a network whose router doesn't send RAs (a lab, an isolated VLAN, a router you can't configure), a DHCPv6 subnet can have LiteBlox's nodes send them: its settings → **Router advertisements → On**. Off is the default.

**What the nodes send:**
- **M** when the subnet hands out addresses (it has pools, or a reserved address), and **O** always;
- the subnet's /64 as on-link, with **A** only when **SLAAC** is ticked ("let devices pick their own address too");
- **router lifetime 0**: the advertisements never offer the node as a **default route**. Clients keep the route from your router, or have none, which suits an isolated network.

So the RA only tells clients to ask DHCPv6. Both nodes of a [failover pair](#the-failover-pair) send them, each on its own interface for the subnet's network.

**Setting it up:**
1. Each node that serves the subnet needs **radvd**: its page → **Repair / upgrade agent**, tick **Router advertisements (radvd)** (`liteblox node bootstrap NAME --dhcp --radvd`). Repair installs `radvd`, stopped, and keeps any `/etc/radvd.conf` of the node's own in `/etc/liteblox-radvd/pre-liteblox/`. If the node can't find the package, Repair stops and names it.
2. On the subnet: a **/64**, **Router advertisements → On**, **Review**, **Apply**. The review shows `radvd.conf` beside Kea's files. A subnet whose serving node has no radvd is refused until that node is repaired.

**How it works on the node:** the agent writes `/etc/liteblox-radvd/radvd.conf` with Kea's files, in the same change (backed up, rolled back together). A systemd path unit (`liteblox-radvd.path`) puts it in place as `/etc/radvd.conf` after `radvd -c`, and then:
- with an interface in it: enables and restarts `radvd`;
- with none (RA off on every subnet there): **stops and disables** `radvd`.

Both the agent and that unit refuse any `radvd.conf` without router lifetime 0, or with anything else LiteBlox doesn't write.

The node's **DHCP** card shows whether radvd is sending and where; the Dashboard's **Services** card shows an **RA on** pill beside the node's DHCP role, and **Needs attention** says when radvd should be running but isn't.

**Turning it off:** **Router advertisements → Off** on the subnet. When no subnet on that node sends them, radvd stops. Clients keep what they learned until it runs out: an address made by SLAAC stays until its lifetime ends (up to a day), and the same goes for unticking **SLAAC** alone.

## DHCPv6 subnets

**Before the first subnet:** every DHCP node needs **Repair / upgrade agent** once after 6.0, which installs `kea-dhcp6-server`. Until then the DHCP tab says which nodes don't run kea-dhcp6 yet, and a subnet isn't served there. With no IPv6 subnet, kea-dhcp6 runs idle and listens nowhere.

**Add one:** DHCP tab → **Add IPv6 subnet**:
- **Subnet**: the prefix (a /64 for a LAN). A DHCP node needs a static address in it on one of its [served interfaces](/help/dhcp#choosing-where-kea-answers), and IPv6 on (a `fe80::` address) on that interface.
- **Pools**: `first - last` or a prefix inside the subnet, one per line. Empty when the subnet only hands out options or delegated prefixes.
- **Delegated prefixes**: see [below](#delegated-prefixes).
- **Options**: DNS servers, search domains, NTP servers (`sntp-servers`). Empty fields use **DHCPv6 settings** (DHCP tab). The DNS field suggests LiteBlox's own DNS nodes that have an address in the subnet (unless BIND is told not to listen on IPv6), and the NTP field the nodes that [serve time](/help/ntp#serving-time) to it.
- **Lifetimes**: how long an address stays *preferred* (used for new connections) and *valid* (the end of the lease), and when the client renews and rebinds. Renew and rebind come before the preferred lifetime runs out.

The subnet's page has the same tabs as an IPv4 one: **Overview**, **Addresses** (leases and reservations in one table, with a CSV export), **Settings**. **Review** shows the change to `kea-dhcp6.conf` on each node; Kea checks it (`kea-dhcp6 -t`) before it's applied, and a failure rolls every node back.

### Delegated prefixes

A router behind LiteBlox (a second router, a lab, a VM host) can ask for a whole prefix to number its own networks: **prefix delegation**. A pool line `fd00:1:2:f000::/52 60` gives out /60s from that /52 (256 of them).

The pool lies outside the subnet's own prefix. **Kea doesn't route:** your router needs a route to each delegated prefix, pointing at the router that got it, or nothing reaches it. Many routers add these by watching DHCPv6; on others it's a static route per delegation (or one for the whole pool, if one router takes them all).

## Reservations: DUID or MAC

A DHCPv6 client is known by its **DUID** (DHCP Unique Identifier), not its MAC. Its lease shows it; **Reserve** on a lease fills it in.

- **DUID**: the surest way. Some systems make a new DUID when they're reinstalled.
- **MAC address**: Kea learns a client's MAC from its packets, its link-local address or its DUID, but not every client gives one. The review warns about it.

A reservation holds an **IPv6 address**, a **delegated prefix** (for a router), or both. With a hostname and neither, it's a **name-only** reservation: the client gets any pool address and is registered under that name. A reserved prefix outside the delegated-prefix pools still works, but the review reminds you the router needs a route to it.

## Registering clients in DNS

A DHCPv6 subnet registers clients the same way an IPv4 one does ([DNS registration](/help/dhcp#registering-clients-in-dns)): an **AAAA** record and a DHCID in the forward zone, and a PTR in the `ip6.arpa` zone that covers the subnet (a /64's zone, `0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa`). The key needs `AAAA DHCID` in the forward zone and `PTR DHCID` in the reverse one; the review lists missing grants.

**The client has to ask:** Kea registers a DHCPv6 client only when it sends the Client FQDN option (option 39) with its name. systemd-networkd (netplan's `dhcp6: true`), NetworkManager and Windows send it. ISC `dhclient` sends none unless its config says so, and it sends a one-label name as a complete one, so Kea doesn't add the domain: give it the full name, ending in a dot:

```
send fqdn.fqdn "laptop.example.lan.";
send fqdn.server-update on;
```

**Turning it off:** **Router advertisements → Off** on the subnet. When no subnet on that node sends them, radvd stops. Clients keep what they learned until it runs out: an address made by SLAAC stays until its lifetime ends (up to a day), and the same goes for unticking **SLAAC** alone.
 a dual-stack client sends the same hostname over DHCPv4 and DHCPv6, but the two DHCIDs differ. On **Kea 2.5 and later**, LiteBlox tells Kea to let a name hold both its A and its AAAA (`check-exists-with-dhcid`) wherever a domain is used by subnets of both families; a name you made by hand is still never touched. **Kea 2.4** (Ubuntu 24.04's) has no such mode: whichever family registers first keeps the name, and the other gets no record.

**Kea before 3.3.1, with both families on one name:** when one family's lease ends, Kea removes its address record but stops before the PTR, because the name still holds the other family's address. The address goes, and a PTR to the name stays in the reverse zone. Search's address card shows it ("The PTR points to another name"). The forward zone's **Stale names** lists it under [PTR records without a name](/help/dynamic#ptr-records-without-a-name), and [reclaiming on a schedule](/help/dynamic#reclaiming-them-on-a-schedule) deletes it. Kea 3.3.1 and later fix it.

## The failover pair

A [failover pair](/help/dhcp#a-failover-pair) serves IPv6 subnets too, once both nodes run kea-dhcp6. DHCPv6's failover needs a port of its own: **8002** by default (DHCPv4 keeps **8001**), set beside the other on the pair's form. Open both between the link addresses. The DHCP tab shows each family's state; the health check and Needs attention watch both.

A change that both servers reload (a subnet, the pair's settings) restarts their failover handshake: for about half a minute neither answers DHCP of either family, until they're back in hot-standby. Clients retry, and leases in hand keep working. The job waits for hot-standby and says so.

## Not in 6.0 yet

The **Leases** page, stale-name reclamation, Move address, next free / assign (and lbcli's `next` and `reserve`) and the device page's DHCP section are IPv4 only; each DHCPv6 subnet's **Addresses** tab has its leases, and the DHCP page's IPv6 section exports them all as CSV.
