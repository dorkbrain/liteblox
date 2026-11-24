# Search

The search box in the top bar (press **/** to get to it) looks through everything LiteBlox knows at once: every zone's records, the DHCP and DHCPv6 reservations and leases, and the zones and subnets themselves. Read-only accounts can search too.

## What a query matches

LiteBlox first decides what you typed, and says so above the results:

| You type | Read as | Matches |
|---|---|---|
| `192.168.1.20`, `fd00:1:2:100::50` | an IP address | A or AAAA records with that address, the PTR record for it, reservations and leases on it, the reverse zone and the subnet it's in. Inside text (an SPF record, a comment) only the whole address matches: `192.168.1.2` doesn't find `192.168.1.20`. An IPv6 address matches however it's written (`fd00:1:2:100:0:0:0:50` too, or in brackets). |
| `192.168.1.0/24`, `fd00:1:2:100::/64` | a network | A/AAAA records, PTR records, reservations and leases inside it (a DHCPv6 delegated prefix too), and the reverse zones (`in-addr.arpa`, `ip6.arpa`) and subnets that overlap it |
| `52:54:00:12:34:56`, `5254.0012.3456`, `52-54-00` | a MAC address, whole or the start of one | reservations and leases with that MAC, whatever separators each side uses |
| `00:01:00:01:2c:4f:aa:bb:52:54:00:12:34:56` | a DHCPv6 client's DUID (colon-separated hex), whole or the start of one | DHCPv6 reservations and leases with that DUID |
| anything else | text | part of a name (`pc1`, `pc1.example.com`), of a record's value (a CNAME, MX or SRV target, TXT), of a comment, a reservation's or lease's hostname, a zone's name or [notes](/help/editing#zone-notes), a subnet's comment, a [device's](/help/ipam#devices) label or comment |

Text matches ignore case, and a name can be typed with or without its zone (`www` or `www.example.com`; a trailing dot doesn't matter). Each result links to where it lives: a record opens its zone's Records tab with the filter already set to its name, and a reservation or lease opens its subnet's Addresses tab filtered to its address.

A query needs at least 2 characters, and at least 3 for what's [read live](#where-the-results-come-from).

## One address

Searching for a single address (IPv4 or IPv6) also shows a card with everything about it: the names pointing at it, its PTR record (and the reverse zone that holds it), its reservation, its lease, and the subnet and whether it's in a pool. Underneath, LiteBlox says what doesn't add up:

- **No PTR record**: a name points at the address, and LiteBlox has the reverse zone for it, but there's no PTR. (Without a reverse zone in LiteBlox it's only a note.)
- **The PTR points to another name**: the PTR names something that has no A (or AAAA) record for this address.
- **Reserved for one MAC, leased to another**: a client got the address before the reservation was made. It moves when that lease ends.
- **The lease's hostname isn't in DNS**: the subnet registers its clients in DNS, but this one's name doesn't point here.
- **A static name inside a pool**: an A record points into a DHCP pool with no reservation behind it, so DHCP can hand the address to another client.

These only report; the links take you to where you'd fix them. An address nothing uses says so, and whether DHCP can lease it.

### Moving an address

**Move to…** on the card (and **Move…** on an IPAM network's address row) gives an IPv4 address a new one, everywhere at once (not IPv6 yet). Enter the new address and **Preview** shows what changes:

- **A records** with the address, in every static zone, get the new address. Their comments and TTLs stay.
- **PTR records** follow, whatever each zone's automatic-PTR setting: the old address's PTR goes, and the new one's is added in the reverse zone LiteBlox holds for it. A PTR that points at a name with no A record here moves on its own, unless a moved name takes the new address's PTR.
- **The reservation** (ticked by default) moves to the new address. If the new address is in another subnet, it moves to that subnet. This is a DHCP job that starts at once. A client keeps its lease until it renews.
- **What IPAM keeps** for the address moves too (ticked by default): its IPAM record or assignment, and its comment.
- **Dynamic zones** are listed but left alone: DHCP (or whoever updates the zone) owns those names.

The preview warns when the new address looks used: a name already points at it, it's reserved or leased, IPAM names it, the nodes have seen it, or it's in a DHCP pool. The DNS changes go into the drafts of every zone they touch, linked so that one **Review** shows them all and one publish sends them. A zone that already had a draft says so, since its pending changes go out with the move. Nothing is changed when a record can't take the new address, or when anything changed since the preview.

## Where the results come from

- **Static zones**: the records as the zone's grid shows them, so a zone with an unpublished draft is searched in its draft (marked **draft**).
- **Dynamic zones**: read from the zone's primary as named serves it now. If the primary doesn't answer, or the health check already finds it down, LiteBlox searches the zone's last saved version from its [history](/help/editing#history) instead and marks the results **as of** that time.
- **Leases**: read live from Kea, kea-dhcp4 and kea-dhcp6 (a failover pair's from its primary, or the standby when the primary doesn't answer). Expired and released leases stay in Kea for a while; they show only when you search for their exact address or MAC.
- **Reservations, zones and subnets**: from LiteBlox's own database.

Each group shows up to 200 results; narrow the search to see the rest.

## From the API

`GET /api/v1/search?q=…` returns the same groups as JSON, and the address card as `address` for an IP query. See [the API](/help/api#search).
