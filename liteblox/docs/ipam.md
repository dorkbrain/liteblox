# IPAM (addresses)

**IPAM** shows what uses each address in your networks: the DNS names pointing at it, its DHCP reservation, the lease a client holds on it, what the nodes have seen there, and which addresses are still free. DNS and DHCP are read live from what LiteBlox already knows, so nothing has to be entered twice and nothing drifts.

IPAM covers IPv4 only.

## Networks

IPAM shows only the networks you add, under **IPAM → Add a network** (for example `192.168.10.0/24`, with a name such as *IoT*). The left side of every IPAM page lists them; on a phone it's a picker above the page.

**Not in IPAM yet**, below the list, offers each DHCP subnet and each reverse zone (`10.168.192.in-addr.arpa` is `192.168.10.0/24`) that no network covers yet: **Add** adds it as it is.

A network can be from a /8 to a /30. Its prefix doesn't change once it's added: to change it, add the new network and delete the old one.

### Nesting and sites

Networks nest by their prefixes alone. A network inside another goes under it, at any depth:
- adding `192.168.0.0/16` after `192.168.1.0/24` and `192.168.10.0/24` puts both under it
- deleting the /16 moves them back up a level

A network that holds others is a **container**: it holds no addresses or ranges of its own, and its page shows how much of it its networks cover. A site is simply a top-level container with the site's name (*Home*, *Cabin*), with its networks inside.

A network that already has ranges of its own can't take a network inside it (its ranges would have nowhere to go): delete them first.

## A network's page

The top row has two cards:
- **Overview**, the address map: one cell per address, 256 at a time (one /24), coloured by what uses it. A range's addresses have a coloured band underneath, an address with something to check is outlined, and clicking a cell jumps to its row. A network bigger than a /24 has a strip of blocks above the map, one per /24, shaded by how full each is: click one to show it.
- **Utilization**: how many addresses are reserved, named in IPAM, leased, used in DNS only, only seen by the nodes, and free.

Below them, **Addresses** lists every address of the shown /24, used or free, with:

| Column | What it shows |
|---|---|
| State | **Reserved** (a DHCP reservation), **Named** (an [IPAM record](#ipam-records)), **Leased** (an active lease, no reservation), **DNS** (a name or a PTR, no DHCP), **Seen** (only the nodes know it's there: see [Devices seen](#devices-seen)), or **Free** |
| Names | The A records at the address, in every zone, its IPAM record (**IPAM**), a client's DHCP hostname when nothing else names it, and the name its PTR at the resolver gives (**rDNS**, see [PTR lookups](#ptr-lookups-rdns)) |
| MAC | The reservation's, the lease's, the IPAM record's, or the one the nodes saw, with its vendor underneath |
| Last seen | When a node last saw a device there |
| DHCP | The reservation or lease |
| Range | The named range the address is in |
| Comment | The address's one comment (see below) |
| Checks | What doesn't add up (see below) |

**Used only** hides the free addresses. The filter box and the column headings work as on the DHCP **Addresses** tab.

**First available** jumps to the lowest Free address in the network with no name in DNS, on whichever /24 it's on, and highlights its row (Used only is turned off). Nothing in LiteBlox uses it, no device has been seen on it lately, and the resolver's PTR lookup (rDNS) found no name for it either. **Check** on its row pings it to be sure, and an address in a DHCP pool can still be handed out at any time. With no free address left, it says so instead.

**Export CSV** downloads the whole network, every /24 of it, not just the one shown (with **Used only** on, the used addresses only), with the columns `ip,state,names,ipam_name,rdns,ptr,mac,vendor,hostname,range,comment,comment_from,last_seen,flapping,checks`: the same fields as [the API](/help/api) gives, several values in a cell separated by `; `. A network bigger than a /16 exports its used addresses only. As in [the DHCP exports](/help/dhcp#leases-and-reservations), a cell that would start a spreadsheet formula gets a `'` in front.

The network and broadcast addresses show in the list but are never counted.

### Ranges

The network's **Settings** names parts of it: **Static** hosts, **Infrastructure** (routers, switches), **Reserved** (kept back), or **Other**. Ranges can't overlap each other or a DHCP pool.

The DHCP pools show as ranges too, read from the DHCP subnets in the network; they change only on the DHCP pages.

### Comments

Each address has one comment, kept where the address's own data lives:
1. on its A record, when it has one in a static zone (the `; comment` at the end of the line, as the zone's grid shows it)
2. else on its DHCP reservation
3. else on its [IPAM record](#ipam-records)
4. else as an IPAM note: for a free address kept for something, or a name in a dynamic zone (named keeps no comments)

The small line under the comment says which. **Edit** saves it there: a record's comment goes into the zone's draft, to publish as any other change; a reservation's is LiteBlox's own, so nothing is written to Kea. A comment changed in the zone grid or the reservation form shows here at once, since there's only one copy.

### Checks

IPAM warns, it never blocks: a home network has good reasons for most oddities. The checks, also on the address card in [Search](/help/search):
- a name with no PTR record, or a PTR pointing to a name that doesn't have this address
- a reservation whose hostname isn't the name DNS has for the address
- a reservation held by another client's lease
- a DHCP client's hostname that isn't in DNS, in a subnet that registers names
- a name in DNS for an address in a DHCP pool with no reservation: DHCP can hand it to another client
- a reservation for one MAC while the nodes last saw another there (not when that one is a [repeater's MAC](#repeater-macs))
- a device seen in a **Static** range with no name in DNS or IPAM: an unknown device?
- an IPAM record whose name isn't the one the address's PTR at the resolver gives
- an IPAM record with a MAC while the nodes last saw another there (not when that one is a repeater's MAC)

The same warnings show when you save:
- an **A record** at an address reserved for another host, or in a DHCP pool with no reservation
- a **reservation** for an address DNS already names for another host, or where the nodes saw another MAC in the last day (a repeater's MAC aside)

### IPAM records

An **IPAM record** is a name kept in IPAM only, with an optional MAC and a comment: for an install that runs no DNS (the DNS module is off, see [Modules](/help/modules)), or an address no zone in LiteBlox covers. Nothing goes to DNS or DHCP.
- **Name…** in an address's row (or **Name this address…** on its card in [Search](/help/search)) adds one; **Name** changes or removes it. With the DNS module on, it's offered only for addresses no reverse zone in LiteBlox covers: elsewhere an A record in the zone is the name's home.
- The address shows as **Named**, search finds it by address, name, MAC or comment, and next free counts it as used.
- With a MAC, IPAM warns when the nodes see another device on the address.
- An IPAM note already on the address becomes the record's comment.
- **Name** links to [Add DNS…](#add-dns) for the address when a zone covers it.
- **Assign** (the API, `lbcli.py reserve`) writes IPAM records when the DNS module is off, or when `target: "ipam"` (`--ipam`) is asked. A MAC in a DHCP subnet still makes a DHCP reservation; a MAC outside them stays on the IPAM record. **Unassign** removes them.

### Add DNS

**Add DNS…** in a row with no name in DNS yet (free, leased, seen, named in IPAM, or reserved without a name) adds an A record for the address, without going to the zone's page. It's offered with the DNS module on and a forward zone in LiteBlox, static or dynamic.
- **Name**: short (`vm03`) for the zone you pick, or a full name in one of LiteBlox's zones, which then goes in that zone. It starts with the address's IPAM name, or its reservation's or lease's hostname.
- **Zone**: the forward zones, the dynamic ones marked. It starts with the static zone most of the network's names are in (a dynamic one only when no static zone has names there).
    - In a **static** zone the record goes into the draft.
    - In a **dynamic** zone (one DHCP registers clients in, say) it's sent as an update and is live at once. DHCP leaves it alone: [reclaiming](/help/dynamic#stale-dhcp-names) only removes names Kea registered (the ones with a DHCID beside them), and Kea won't register a client over a name it didn't add.
- **Comment**, saved on the A record; it starts with the address's IPAM or note comment.
- **PTR**: also add the PTR in the reverse zone that covers the address, ticked when the zone has **Sync PTR records** on (its Settings). Off when no reverse zone in LiteBlox covers it.
- **Then**, when a static zone holds the change (the zone itself, or the reverse zone for a dynamic zone's PTR): **Publish now** (a publish job; the notice links to it), or **Leave it in the draft**, to review and publish on the zone's page.

It's the same record as one added on the zone's page: a name that already points elsewhere is allowed, with the zone page's warning, and the record isn't tied to IPAM afterwards (the zone is where it's changed or deleted). An IPAM record on the address stays until you remove it.

**Move…** on a row that holds something (a name, a reservation or an IPAM record) gives the address a new one everywhere: see [Moving an address](/help/search#moving-an-address).

### PTR lookups (rDNS)

With a **Resolver** in Settings → IPAM, LiteBlox asks that DNS server for the PTR of each used address: for names that live in DNS LiteBlox doesn't run (your router's, another DNS server's). The name shows as **rDNS** in the network's table, on the address card and in Devices seen.
- A network's page looks up its used addresses whose answer is older than **Look up again after** (24 hours) when it opens: at most 256 at a time, in the background, so the page never waits (reload it to see new names). The address card looks up its address the same way.
- A sweep looks up the addresses that answered, and its job log says how many had a name.
- A failed lookup (no answer in 2 seconds, SERVFAIL) is tried again after an hour. Changing the resolver forgets the names the old one gave.
- With the DNS module on, the zones stay where names come from; lookups are optional and off by default.

### Check (is it really free?)

**Check** on a free address asks a LiteBlox node on that network to ping it once and read its neighbour (ARP) table:
- **answers**: something replied to the ping
- **no ping reply, but … answers ARP**: a device that drops pings is there anyway
- **nothing answers**: nothing replied while it was checked

Only a node with an interface on the network can check it: the page says which nodes see it. A network elsewhere (a remote site) shows its DNS and DHCP only. Agents older than 3.4 can't check: **Repair / upgrade agent** on the node's page.

### Next free

The API and [lbcli.py](/help/api#the-command-line-lbcli) can ask for the next free address in a network, a range or a DHCP subnet, or a block of up to 64 in a row:
- On paper, an address is used when DNS has a record for it, DHCP a reservation or an active lease, a node or a router has it, it's held, or the nodes saw something there in the last 7 days. DHCP pools and reserved and infrastructure ranges are left out, so a DHCP subnet offers only the addresses outside its pools (for a reservation).
- Then a node on the network probes the candidates: an address is in use if it answers a ping, or answers ARP during the probe (a device that drops pings). What answers is recorded as seen.
- The address is **held** for 10 minutes, so two callers never get the same one. **Assign** then puts a name on it: an A record (and PTR), or a DHCP reservation when a MAC is given. **Unassign** removes exactly what assign made, by address, range or group.

A network no node is on can't be probed: the address comes back marked as not checked.

### The sweep

A network's **Settings** can sweep it **hourly** or **daily** (off by default): a node on the network probes every address, 64 at a time at 10 a second, so quiet devices show up in Devices seen. **Sweep now** runs one at once, as a job. Networks bigger than a /22 aren't swept. A device the node talked to in the last few minutes that drops pings may not answer in time, but it's already in Devices seen from the node's neighbour table.

## Devices seen

Every minute the health check reads each node's neighbour (ARP) table, the devices it has talked to lately on its networks, and keeps each address's MACs for 7 days. An address seen in the last 24 hours, with nothing else on it, counts as **in use** (`seen`) on the network pages; one seen earlier shows as free there, with its MAC and when it was last seen, but next free still passes it over until it's dropped. **IPAM → Devices seen** lists one row per MAC, like an ARP monitor: its address, vendor, DNS name, when it was first and last seen and by which node, and the addresses it had before.

What it can and can't see:
- **A node sees only the networks it's on**, and only devices it has exchanged traffic with: a DHCP server talks to every client that gets a lease, and DNS clients ask it, so most devices show up. A quiet device on a network shows up once something there reaches it.
- **Last seen** is when the node last had the device confirmed (it answered ARP or sent the node traffic), not when the node last remembered it. A node keeps an entry for a while after the device leaves, and that doesn't count.
- A network elsewhere (a remote site) has nothing seen.

**Export CSV** downloads the devices the filter shows, with the columns `ip,mac,vendor,label,comment,names,network,first_seen,last_seen,node,source,earlier_ips,flapping,expected,repeater`.

**Forget** drops a MAC from an address at once (a device that's gone for good); it comes back if a node sees it again.

### Flapping

When an address's MAC keeps changing, two devices are probably using it (a static address typed twice, a device with the wrong address). **3 changes within 10 minutes** puts the address in **Needs attention** on the Dashboard. Its address card (Search) shows the MACs and its history of changes; **Acknowledge** takes it off the list, and it comes back only if the address flaps again after that.

One read a minute catches a conflict that lasts a few minutes; a short one can slip by.

Some addresses have several MACs on purpose: a computer with two network cards on the same network (Linux answers ARP from both by default), a bond that hands out different MACs, or a failover address (a Wi-Fi repeater's MAC is better marked [as a repeater's](#repeater-macs)). For those, **These MACs are expected here** (with an optional reason) on the address card mutes the changes between the MACs it has seen, for good. A change to any other MAC still raises it, so a real conflict isn't hidden. The address card and Devices seen mark those MACs **expected**; **Unmute** on the card makes every change count again. Forget doesn't clear it.

### Repeater MACs

Many Wi-Fi repeaters and range extenders translate MACs: on your network they answer with one MAC of their own for every device connected through them, while DHCP still sees each device's real MAC. That MAC is often a "private address" one (a made-up MAC, its vendor unknown), and it turns up on the repeater's own address and on the address of whatever is connected through it right now. So a reserved device behind the repeater looks like "reserved for its MAC, but the nodes last saw another", and a phone that moves between your main Wi-Fi and the repeater looks like it's flapping.

Mark that MAC once, on its device page (click it on Devices seen): tick **Wi-Fi repeater** and save. From then on, wherever it shows:
- a change to or from it isn't flapping (a change between two other MACs still is)
- it raises no "reserved for" or "IPAM has it for" warning, and saving a reservation doesn't warn about it
- it still counts as in use, next free still passes over it, and its history is kept

Devices seen marks it **repeater**, and the line under it reads **Wi-Fi repeater** everywhere the MAC shows. Untick it to make it count again. For an address that has several MACs of its own (two network cards, a bond), use expected MACs instead.

## Devices

A MAC's page (click a MAC on Devices seen, in a network's table or on a subnet's Addresses tab) shows what LiteBlox knows of that device: its label and comment, its vendor, its reservations and leases in each DHCP subnet, the DNS names at its address, and every address the nodes have seen it on.

A **label** ("Kitchen tablet") shows next to the MAC everywhere, with its vendor, and search finds it, along with the comment. It changes nothing in DNS or DHCP. Devices seen has a **Label** button on each row for labelling as you go.

The page also offers the next step for each subnet the device is in, each reviewed and applied like any [reservation](/help/dhcp#reservations):
- **Register a name** (subnets that register clients in DNS): a [name-only reservation](/help/dhcp#name-only-reservations). The device keeps taking any pool address and is always in DNS under the name you pick (from its label, to start with).
- **Reserve** its current address, or **Fix its address** when it has a name only: it gets that address every time.
- **Back down to a name** from a fixed address, or **Back down** from a name only (the reservation goes).

### MAC vendors

The vendor under a MAC comes from the IEEE's list of assigned prefixes, which LiteBlox fetches into its data folder and fetches again every week (it needs to reach `standards-oui.ieee.org`). A MAC its device made up has no vendor and shows as a **private address**: phones and laptops do this, often one per network.

### Settings → IPAM

- **Keep for**: how long an address or MAC nobody has seen stays (7 days): in Devices seen, on the address cards, and for next free.
- **Counts as in use for**: how long a seen address with nothing else on it (no name, lease or reservation) counts as used on the network pages, in the map, the donut and the used counts (24 hours; at most Keep for). Lower it when devices hop between pool addresses and fill the map with old sightings.
- **Flapping**: the number of MAC changes within a number of minutes (3 in 10).
- **Resolver** and **Look up again after**: [PTR lookups](#ptr-lookups-rdns), off until a resolver is set (`192.168.1.1`, or `192.168.1.1:5353` for another port).
- **Keep a DHCP name while the nodes still see its address** (on by default): a [stale DHCP name](/help/dynamic#stale-dhcp-names) whose address a node saw within its zone's reclaim time is kept.
- **MAC vendors**: the list's date, and **Fetch now**.

## Who can change what

Read-only users see every IPAM page and change nothing. Adding and deleting networks, ranges, IPAM records and comments, labels, repeater MACs, Forget, Acknowledge, expected MACs, sweeps and the settings are admin-only and go in the [audit log](/audit). Deleting a network only takes it out of IPAM: records, DHCP and notes stay.
