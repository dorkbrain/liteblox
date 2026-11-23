# Zones and their settings

LiteBlox declares every zone itself, in `/etc/bind/liteblox/zones.conf` on each node that serves it. A forward or reverse zone's file lives on the primary (`/etc/bind/liteblox/db.<zone>`, or under `/var/lib/bind/liteblox/dyn/` for a [dynamic zone](/help/dynamic)); each secondary keeps its own copy, transferred from the primary, in `/var/lib/bind/liteblox/sec/`.

## The Zones list

Each zone shows what kind it is (**reverse**, **dynamic**, **forwarding**, and **draft** when it has unpublished changes), its published serial and the serial each node serves. The links above the list show only one kind (Forward, Reverse, Dynamic, Forwarding, Drafts), each with its count; the page's address keeps the choice, so you can bookmark it.

**Export CSV** downloads the records of every zone in the list (or of the kind shown) in one file, with the columns `zone,name,ttl,type,value,comment`. The names are relative to their zone, as in [a zone's own export](/help/editing#adding-many-records), so one zone's rows, without the `zone` column, go back in through **Add many**. Forwarding zones have no records. A zone that couldn't be read (a draft that doesn't parse, a dynamic zone whose primary doesn't answer) is left out, with a `#` line at the top saying why.

## Every zone change

Creating a zone, adding or removing a node, changing its settings and deleting it all work the same way:

1. Each affected node is **backed up**. If a backup fails, nothing is changed.
2. Each node's new configuration is **staged**: the agent checks every file against its allow-list and runs `named-checkconf` on the whole set. A refusal anywhere cancels the change everywhere.
3. Each node **commits**: writes the files and runs `rndc reconfig`, restoring its previous files if that fails.
4. LiteBlox checks over DNS that each node serves (or no longer serves) the zone, and that secondaries have transferred it.

## Creating a zone

**Zones → Add zone**, then choose a kind:

- **Forward lookup → Zone name**: e.g. `example.com`
- **Reverse lookup → Network**: e.g. `192.168.1.0/24`. LiteBlox works out the zone name (`1.168.192.in-addr.arpa`) and shows it as you type. IPv4 networks must be a /8, /16 or /24 (a /23 needs two /24 zones; classless delegation of smaller networks isn't supported). IPv6 prefixes must be a multiple of 4 (`2001:db8::/32` → `8.b.d.0.1.0.0.2.ip6.arpa`).
- **Forwarding only → Domain**: see [Forwarding-only zones](#forwarding-only-zones).

For a forward or reverse zone:

- **Nameservers**: one per line. A name inside the zone needs its address on the same line (`ns1.example.com 192.168.1.213`); LiteBlox adds the A/AAAA record for it. A reverse zone's nameservers live in a forward zone, so they need no address.
- **Responsible mailbox**: optional. It defaults to `hostmaster.<zone>`, or for reverse zones `hostmaster.<nameservers' domain>`.
- **Default TTL**: 3600 unless you change it
- **Serve it on**: the nodes to declare it on. The primary always serves every zone, so it's ticked and can't be unticked; the other nodes you tick become its secondaries.

The new zone is [kept sorted](/help/editing#records-are-kept-sorted), like every static zone. It starts with an SOA (serial `YYYYMMDD01`, refresh 3600, retry 900, expire 1209600, negative TTL 300), the NS records and any nameserver addresses. When the job finishes, **Open ZONE** takes you to it.

Without a primary picked yet, every node you tick holds its own primary copy and gets every publish. Pick a primary on the **Nodes** page to switch to one primary with secondaries.

## Forwarding-only zones

A **forwarding-only** zone sends queries for a domain, and every name under it, to other servers instead of resolving them the normal way: for example a company domain answered by its own DNS servers over a VPN. It has no records in LiteBlox and no primary; every node you pick forwards it the same way.

- **Forwarders**: one IP address per line, optionally followed by `port N`
- **When the forwarders don't answer**: **fail (forward only)**, or **look it up the normal way (forward first)**
- **Don't DNSSEC-validate this domain** (ticked by default) adds the domain to `validate-except` on those nodes. A private domain such as `corp` or `home.lab` doesn't exist in the public DNS, so validating the forwarders' answers would fail.
- **Forward it on**: the nodes. Forwarding is part of recursion: clients only get forwarded answers from a node that lets them recurse (`allow-recursion` in [Server settings](/help/server-settings)). The form warns about a node with recursion off.

Its **Settings** tab has the forwarders, the nodes and the Danger zone; there's nothing to edit, review or publish.

## Adding and removing nodes

- **Add a node** (in the **Nodes** section of the zone's Settings tab) declares the zone on another taken-over node. With a primary, it becomes a secondary and transfers the zone; without one, it gets the published copy.
- **Stop serving on a node** (in the [Danger zone](#deleting-a-zone)) stops declaring the zone on the node you pick. The primary serves every zone, so it isn't listed. The zone file stays on the node's disk.

## Settings

The zone's **Settings** tab:

- **Sync PTR records**: whether edits to A/AAAA records here update the matching reverse zone. It's stored in LiteBlox only.
- **Notes**: plain text about the zone, [kept in LiteBlox only](/help/editing#zone-notes).
- **Dynamic updates**: see [Dynamic zones and TSIG keys](/help/dynamic).
- **Declaration**, written into `zones.conf` on every node serving the zone:
    - **notify**: the primary always notifies LiteBlox's own secondaries. `explicit` adds the **Also notify** list, `yes` adds the zone's NS records and the list. "not set" leaves BIND's default (yes).
    - **Also notify**: addresses, one per line, for secondaries outside LiteBlox
    - **Allow transfers to**: addresses, networks, ACL names or `key NAME`, one per line, for other servers that copy the zone. LiteBlox's own secondaries are always allowed, with LiteBlox's key.
    - **Answer queries from**: who may query this zone; empty uses the node's own setting. LiteBlox keeps its secondaries and its own checks working through a restricted list.

**Save and apply to nodes** rewrites `zones.conf` on every node serving the zone, through the same backed-up, staged process. The current declaration on the primary is shown under the form.

## Deleting a zone

The **Danger zone** at the bottom of a zone's **Settings** tab has **Delete this zone**. Type the zone's name to enable the button.

LiteBlox removes the declaration from every node serving it, through the same backed-up, staged process, and checks they no longer serve it. Every node must be reachable; if one is gone for good, [remove that node](/help/troubleshooting#removing-a-node) first. The zone files stay on the nodes. A forwarding-only zone's `validate-except` entry goes too.

Any draft is discarded and the zone's history stays in the zone repository. Creating or importing a zone with the same name later brings the older versions back under **History**, where you can restore one into a draft.
