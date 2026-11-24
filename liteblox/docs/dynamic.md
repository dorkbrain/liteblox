# Dynamic zones and TSIG keys

A **dynamic** zone accepts DNS updates (RFC 2136): a DHCP server registers its clients' names, an ACME client proves it owns a name with a TXT record, `nsupdate` changes a record from a script. Each of them signs its updates with a **TSIG key**, and LiteBlox decides what each key may change.

A zone of their own (`dhcp.example.com` for DHCP clients, say) is a good idea but not required: it keeps machines' records apart from the ones you maintain by hand, and your main zone keeps its [sorted](/help/editing#records-are-kept-sorted) order and the comments on its records' lines.

## Switching a zone to dynamic

On the zone's **Settings** tab, **Dynamic updates → Switch on**. It needs:

- a primary that serves the zone, with every other node serving it a secondary
- no open draft (publish or discard it first)

LiteBlox backs the nodes up, moves the zone's file on the primary to `/var/lib/bind/liteblox/dyn/db.<zone>` (where named may write it and its journal) and declares it with an `update-policy` that lets LiteBlox's own key change anything, plus the [grants](#grants) you've given other keys. Secondaries are unchanged: they keep transferring the zone, and named sends them each update as an incremental transfer.

From then on **named rewrites the file**: comments and your record order are gone, and the file is in named's own order.

**Switch off** turns it back into a static zone: what named serves at that moment becomes the published copy in `/etc/bind/liteblox/`, and updates from other keys stop. Grants for the zone are kept, shown as *inactive*, and apply again if you switch it back on.

## Editing a dynamic zone

The grid looks and works the same, with these differences:

- **Edits apply at once.** Each save is sent to the primary as one signed update. There's no draft, Review or Publish for a dynamic zone; the Raw tab is read-only.
- **Each update is guarded, but only on what it touches.** A busy zone changes all the time (every DHCP lease bumps the serial), so an edit isn't refused because *something* changed since you loaded the page. It applies as long as the record set you're changing (same name and type) is still exactly what the page showed:
    - Someone else changed **that** record set since then: you get *That record changed on the server since you loaded the page … nothing was written*. Reload and redo it.
    - A **new** record is always added, whatever else changed.
    - In the **SOA** card, the serial doesn't count, since named moves it with every update. Only the fields you can edit do.
- **The serial** goes up by one with every update (named does it). An SOA edit in the card is sent with the serial one past the current one.
- **Ticking rows** offers only **Delete**, sent as one update ([Selecting rows](/help/editing#selecting-rows)). **Add many** is for static zones; a script can make many changes to a dynamic zone in one update with the [API's batch call](/help/api#many-changes-at-once).
- **Stale names** lists the names DHCP registered and left behind: see [Stale DHCP names](#stale-dhcp-names).

## History

named owns the file, so LiteBlox keeps the history from what named serves:

- every LiteBlox edit becomes a version (`Edit (serial N)`), by whoever made it
- just before it, whatever changed since the last version (leases, certificates, `nsupdate`) is committed as `Snapshot (serial N)` by `liteblox`, so your version holds only your edit
- a daily pass, after the scheduled backups, commits a snapshot of every dynamic zone that changed

**Compare** works as for any zone. **Restore** sends the difference between that version and the zone now as one guarded update, instead of making a draft.

## TSIG keys

**Settings → TSIG keys** lists every key LiteBlox writes into `keys.conf` on each node it has taken over:

| Key | What it's for |
|---|---|
| `liteblox-xfr` | LiteBlox's own: signs zone transfers from the primary to its secondaries |
| `liteblox` | LiteBlox's own: it reads dynamic zones with it and sends grid edits as updates |
| imported | keys found in a server's configuration when it was [taken over](/help/existing-servers) |
| client keys | the ones you create for DHCP, ACME and other clients |

LiteBlox's own keys are created when you first pick a primary, and their secrets never leave LiteBlox and its nodes.

### Add a client key

**Add a client key**: a **Name** (what the client puts in its configuration, such as `dhcp` or `acme-web`) and an **Algorithm** (`hmac-sha256` unless the client needs another). **Add key** writes it to every node and shows the secret **once**, with **Download NAME.key** (BIND's key-file format, which `nsupdate -k` reads). Only you see that page, and it's gone once you click **I've saved it**, or after 10 minutes. If the secret is lost, **Replace secret** makes a new one and shows it once in the same way; the old one stops working.

**Delete** removes the key and its grants from every node. A key still named in a list (for example a zone's **Allow transfers to**) can't be deleted until it's taken out.

### Grants

A key can't change anything until it's granted. On the key, **Grant a zone**:

- **Zone**: any zone; a grant on a static zone is kept but only takes effect while the zone is dynamic
- **What**: **the whole zone**, **names under…** a name (and that name itself), or **only the name…**
- **Types**: record types separated by spaces; `ANY` for all

Each grant becomes a line in the zone's `update-policy` on the primary, for example `grant dhcp zonesub A AAAA DHCID;`. **Revoke** takes it out again. An update a key isn't granted is refused by named (`REFUSED`), and nothing changes.

Typical grants:

| Client | Zone | What | Types |
|---|---|---|---|
| DHCP (forward) | `dhcp.example.com` | the whole zone | `A AAAA DHCID` |
| DHCP (reverse) | `0.168.192.in-addr.arpa` | the whole zone | `PTR DHCID` |
| ACME for one name | `example.com` | only the name `_acme-challenge.www.example.com` | `TXT` |

From the command line: `liteblox key add|grant|revoke|delete|list` ([reference](/help/reference#tsig-keys)).

## Clients

Updates go to the **primary**. After a [promote](/help/failover), point your clients at the new primary. LiteBlox's own DHCP needs none of this: see [Registering clients in DNS](/help/dhcp#registering-clients-in-dns).

**nsupdate**, with the downloaded key file:

```bash
nsupdate -k dhcp.key <<'EOF'
server 192.168.1.213
zone dhcp.example.com
update add laptop.dhcp.example.com 300 A 192.168.0.51
send
EOF
```

**Kea**: its DHCP-DDNS server (`kea-dhcp-ddns`) takes the key's name, algorithm and secret from the key file:

```json
"tsig-keys": [
    { "name": "dhcp", "algorithm": "HMAC-SHA256", "secret": "…from dhcp.key…" }
],
"forward-ddns": {
    "ddns-domains": [
        { "name": "dhcp.example.com.", "key-name": "dhcp",
          "dns-servers": [ { "ip-address": "192.168.1.213" } ] }
    ]
},
"reverse-ddns": {
    "ddns-domains": [
        { "name": "0.168.192.in-addr.arpa.", "key-name": "dhcp",
          "dns-servers": [ { "ip-address": "192.168.1.213" } ] }
    ]
}
```

**ACME** clients with an RFC 2136 plugin (certbot's `dns-rfc2136`, lego's `rfc2136`) take the same server, key name, algorithm and secret.

## PTR records across static and dynamic zones

**Sync PTR** works between any two zones; when the PTR lands depends on both:

| Forward zone | Reverse zone | The PTR change |
|---|---|---|
| static | static | goes into the reverse zone's draft, linked: both are reviewed and published together |
| static | dynamic | waits with the forward zone's draft (Review lists it) and is sent as an update once that publish succeeds; discarding the draft drops it. If the update fails, see [below](#ptr-updates-that-didnt-go-out). |
| dynamic | dynamic | applies at once, like the edit |
| dynamic | static | goes into the reverse zone's draft, with a note to publish it there |

### PTR updates that didn't go out

When the forward zone is published but sending its PTR changes fails, the changes stay queued. Causes include the reverse zone's primary being down, or the reverse zone being frozen on it. The forward zone's **Records** tab then shows a **PTR updates that didn't go out** card, with the changes and the error. You can:

- click **Retry** once the cause is fixed (a job sends them)
- click **Drop** to give up on them; the reverse zone keeps what it has

The next publish of the forward zone also sends them again. Discarding a later draft doesn't drop them, because they belong to a publish that already went out.

## Stale DHCP names

Kea removes the name it registered when the lease ends. Sometimes that update is lost: the primary was down, a promote was under way, or Kea's lease file was reset. The name then stays in the zone, pointing at an address someone else may get. **Stale names** above the grid of a dynamic zone lists the names Kea registered (an A or AAAA record with a **DHCID** beside it) and says which are stale. DHCP and DHCPv6 leases and reservations both count.

A name is **stale** when all of these hold:

- no live lease has its name or its address
- no DHCP reservation has its name or its address
- its last lease ended longer ago than the zone's **reclaim time**: by default the longest lease time of the subnets registering into the zone (else the global one), or what you set under **Settings → Stale DHCP names → After**
- with IPAM on and **Keep a DHCP name while the nodes still see its address** ticked (Settings → IPAM, on by default), no node saw its address within the reclaim time. Such a name shows as *no lease, still on the network*.

Kea forgets an expired lease after an hour, so LiteBlox remembers each name's last lease expiry from the health check's lease reads. A name it never saw a lease for counts from when it first noticed it, so after an install or a re-adopt nothing is stale before a full reclaim time has passed. Names nobody gave a DHCID (typed in, ACME, another key's) are never stale.

**Delete the ticked records** removes the stale names at once (tick or untick any): their A, AAAA and DHCID records in one update, and in a dynamic reverse zone LiteBlox holds (`in-addr.arpa` or `ip6.arpa`), the PTR that points at each (with its DHCID). A PTR pointing at another name stays.

### PTR records without a name

The same view lists the PTR records Kea made (a PTR with a DHCID beside it) in a dynamic reverse zone LiteBlox holds that point at a name in this zone, where that name has no A or AAAA record for the address any more. Kea before 3.3.1 leaves one behind when one family of a [dual-stack name](/help/ipv6) goes, and a lost update can leave one too. A PTR is listed under the zone its name belongs to (the most specific zone LiteBlox has for it).

One is **stale** when no live lease and no reservation has its address, and it has pointed at nothing for longer than the zone's reclaim time, counted from when LiteBlox first noticed it. A PTR whose name gets that address back starts over. Deleting one removes the PTR, and its DHCID when no other PTR is left at that address. PTRs you typed in (no DHCID) are never listed.

### Reclaiming them on a schedule

Under the zone's **Settings → Stale DHCP names**, **Reclaim stale DHCP names** (off by default) checks the zone once an hour and deletes its stale names and stale PTR records the same way. Turning it on shows what would go now. A pass that deletes something runs as a **Reclaim** job (user `liteblox`) whose log names each name and address; it's in the audit log too. A pass holds back, deleting nothing:

- while DHCP isn't healthy: a DHCP server doesn't answer or isn't serving, the failover pair isn't in hot-standby, or the leases can't be read
- when more than a quarter of the zone's DHCP names (and at least 4) would go at once, or more than a quarter of the PTR records Kea made for its names: something is more likely wrong than that many clients leaving. **Needs attention** says so and links to the zone's stale names, where you can delete them yourself.

## Dynamic zones on a server you take over

A server you [take over](/help/existing-servers) may already have zones that take updates. LiteBlox imports one when its update rules are TSIG key grants:

- `update-policy { grant KEY zonesub|subdomain|name … TYPES; … };`
- `allow-update { key KEY; … };`, which is the same as `grant KEY zonesub ANY`

Each rule becomes a grant on **Settings → TSIG keys**, and the key comes in with the rest of the server's keys. During the takeover the zone is held with `rndc freeze` for a few seconds, so no update is lost; clients retry. The zone then moves, journal included, to `/var/lib/bind/liteblox/dyn/`.

LiteBlox reads and edits the zone once you pick a primary (**Make … the primary** on the Nodes page). That step also gives LiteBlox's own `liteblox` key its grant. Clients keep updating the zone the whole time.

These block the takeover instead:

- an `allow-update` by address or ACL, `update-policy local`, or rules other than `grant` with `zonesub`/`subdomain`/`name`. Switch those clients to a TSIG key on the server first.
- a primary already picked in LiteBlox, or a zone LiteBlox already has. LiteBlox would have to copy the zone from a snapshot and could lose updates. Move the zone to the primary by hand, or take the server over without it.
