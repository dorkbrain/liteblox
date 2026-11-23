# Editing and publishing

This page is about **static** zones: you edit a draft, review it and publish it. A [dynamic zone](/help/dynamic#editing-a-dynamic-zone) uses the same grid, but each edit applies at once.

## The record grid

Open a zone from **Zones**. A strip under the tabs shows each node serving the zone: the primary (**✓** when it has the published copy, **needs publish** otherwise) and its secondaries, which transfer the zone from it. It also shows whether the zone is dynamic, and the last publish. Below it are the [SOA](#the-soa-card) and [Nameservers](#nameservers) cards, then the **Records** grid with every other record.

- **Filter** narrows rows by name, value or comment; the **type chips** show one type.
- Click a column heading (**Name**, **TTL**, **Type**, **Value**) to sort the grid by it, again to reverse, and a third time to go back to the zone's own order. This only changes the view; the zone file stays [sorted](#records-are-kept-sorted).
- **Edit** turns a row into inputs; **Save** or **Cancel**.
- **Add record** (top) opens a new row; the record goes to its [sorted place](#records-are-kept-sorted) when you save it.
- **Delete** asks first.
- Tick rows to [act on several at once](#selecting-rows), or [add many](#adding-many-records) from pasted lines or a CSV.
- A small **↑** next to a name means the record inherits its name from the line above, as zone files allow.

Some types get their own fields: MX (priority, mail server), SRV (priority, weight, port, target), CAA (flags, tag, value) and TXT. TXT text is quoted for you, and split into 255-character pieces when it's longer. TXT records made of several separate strings show in their quoted form so saving doesn't merge them.

Names are relative to the zone (`www`, or `@` for the zone itself); a name ending in a dot is absolute. For records pointing at a name (CNAME, NS, PTR, MX, SRV), the grid shows the full name a relative value expands to (`web` → `web.example.com.`).

### Selecting rows

Admins get a checkbox on each row. The box in the heading selects **every row shown**, so filter first ("printer", or the **A** chip), then select them all. A bar shows how many are selected:

- **Delete** removes them, after asking (with their PTRs, when the zone keeps PTRs in step).
- **Set TTL** gives them all one TTL; leave the box empty for the zone's default.
- **Set comment** gives them all one comment; leave it empty to clear their comments.

Each is one change to the draft, reviewed and published like any other. Rows the filter hides are never part of it, even if you ticked them earlier. On a [dynamic zone](/help/dynamic) **Delete** is the only action, and it's sent at once as one update: if any of the rows changed on the server since you loaded the page, nothing is deleted.

### Adding many records

**Add many** (above the grid, static zones) takes many records at once, pasted as zone-file lines or from a CSV file:

```
host1 A 192.0.2.10 ; office printer
host2 3600 A 192.0.2.11
www CNAME host1
```

Each line is a name (relative to the zone, `@` for the zone itself), an optional TTL, the type and the value, and an optional `; comment`. Directives like `$ORIGIN` aren't taken: write each record out.

A CSV has the columns `name,ttl,type,value,comment` (the comment column may be left off). **Download a CSV template** gives you the header and sample rows for the zone; rows starting with `#` are skipped, so take the `#` off a sample to use it. **Export CSV** above the grid exports the zone's records in the same shape (with a draft, the draft's records), so a zone can go out to a spreadsheet and come back. The Zones list exports [every zone at once](/help/zones#the-zones-list).

**Preview** checks every line the way the grid would and shows what each one does: **adds**, **skips** (already there), or its **error**, with warnings such as a second A record for a name or an address in a DHCP pool. **Replace** makes the lines the records of each name and type they mention: others with that name and type are **removed**, and a matching record with a new TTL or comment **changes**. Nothing is saved while any line has an error. The changes then go into the draft as one change, with their PTRs, and you land on **Review**.

Scripts can do the same through the [API's batch call](/help/api#many-changes-at-once).

### Checks

A row isn't saved if:

- the value isn't valid for its type (a bad address, an MX without a priority…)
- the name is outside the zone
- the TTL isn't a number of seconds or a duration (`300`, `5m`, `1h`, `1d`, `1h30m`)
- it would put a CNAME next to other records at the same name, or a CNAME at the zone apex

You get a **warning** (but the save goes through) for a value like `host.example.com` without a trailing dot inside `example.com`, which would really mean `host.example.com.example.com.`.

Durations (TTLs and the SOA timers) are shown as `1h`, `15m`, `2w` (hover for the seconds), and you can type them either way. They're written to the file in seconds.

### Records are kept sorted

LiteBlox keeps **every static zone sorted**, so a zone reads the same way whoever edited it last. Every save writes the file in this order:

1. the zone apex: SOA, then NS, then the other apex records
2. every other name in DNS order, so `host.example.com` is followed by `a.host.example.com`. Numbers are compared as numbers, so a reverse zone runs 1, 2, 10.
3. within a name, by type (A, AAAA, CNAME, PTR, MX, SRV, TXT, CAA…), then by value (addresses numerically, MX and SRV by priority)

How the file is written:

- Records you didn't touch keep their exact text. The records themselves never change, only their order.
- A comment at the end of a record's line (`printer9 IN A 192.0.2.109 ; upstairs`) moves with its record.
- A comment block at the very top of the file stays at the top.
- **Other comment lines leave the file** and go to the zone's [notes](#zone-notes). Once sorted, a heading like `; --- printers ---` would end up above the wrong records. Each one is noted with the name it sat above, e.g. `--- printers ---  (above printer9)`. Review lists them before you publish.
- Every record has its name written out, all names are relative to the zone (no `$ORIGIN`), and there's one `$TTL` at the top. A record that relied on a later `$TTL` gets that TTL written on it.
- `$GENERATE` lines (with the comments just above them) keep their order in a block after the records.
- There's a blank line after the apex records.

**A zone that can't be sorted keeps its own order.** This happens for a zone with `$INCLUDE`, a line LiteBlox can't read, or a `$GENERATE` under another `$ORIGIN` or `$TTL`. The Raw tab and the Dashboard's **Needs attention** say why. Write those lines out as records and the next save sorts it.

**Zones from before 3.3.1**, which could keep their own order, are put in order as **drafts** when LiteBlox starts. So are the zones a takeover imports. You see the reordering on **Review** before anything reaches the nodes. A dynamic zone isn't sorted: named owns its file.

### Zone notes

Each zone has **notes**, plain text kept in LiteBlox only: they're never written to the zone file, the nodes or the zone history (the audit log, under **Users**, records each change). Use them for what a group of names is for, or who to ask. They show above the records grid, and you edit them on the zone's **Settings** tab. Comment lines that [sorting](#records-are-kept-sorted) takes out of a zone file are added to them when that draft is published.

### Reverse records (PTR)

With **sync PTR** ticked (the default for A and AAAA rows), saving also updates the matching PTR, if LiteBlox has a reverse zone covering the address. The most specific one is used, so `1.168.192.in-addr.arpa` beats `168.192.in-addr.arpa`.

- **adding** an A record adds its PTR, kept in address order
- **changing** the address or name moves the PTR
- **deleting** the A record removes its PTR
- a name that isn't a host name gets no PTR, because BIND only accepts host names as PTR targets: wildcards (`*.lab`) and names with underscores (`_svc`). The grid says so.

A PTR that already points to a **different** name is never overwritten. The grid tells you, and you can sort it out in the reverse zone. If LiteBlox has no reverse zone for the address, the grid just notes it.

Turn the behaviour off for a whole zone on its **Settings** tab, or untick **sync PTR** for one edit.

## The SOA card

The SOA shows as one line (nameserver, mailbox, timers and serial), so the records start near the top. **Edit** opens it: change the primary nameserver, the mailbox and the timers, then **Save SOA**. The **?** beside each field explains it. **The serial isn't edited by hand**: every publish sets it to today's date (`YYYYMMDDnn`) or, if that isn't higher, to one above anything any node is serving.

## Nameservers

The zone's own NS records (at `@`) are edited in the **Nameservers** card, not the grid. NS records for a delegated subdomain stay in the grid.

- **Add nameserver**: a name ending in a dot, or a name relative to the zone (`ns3`). A name inside the zone also needs an A or AAAA record, which you add in the grid.
- **Remove**: a zone always keeps at least one.

Each nameserver shows its addresses and the LiteBlox node it points at. The addresses come from the zones LiteBlox holds, drafts included, so they reflect what you're about to publish; a name in a zone LiteBlox doesn't hold shows **address not held in LiteBlox**. The card warns when:

- a nameserver inside the zone has no address (the zone wouldn't load)
- a node serves the zone but isn't one of its nameservers, so resolvers never ask it
- a nameserver points somewhere that isn't one of the zone's nodes (just a note: it may be a secondary elsewhere)

## The Raw tab

The whole zone file as text, for anything the grid can't do (`$GENERATE`, `$INCLUDE`, unusual records). Saving goes into the same draft. The file keeps its own line endings (Windows-style or Unix), whatever your browser sends.

## Drafts

Every change to a static zone goes into a draft; nothing reaches a server until you publish. The bar above the grid shows how many changes are pending.

- **Linked drafts**: a PTR change made by an edit here puts the reverse zone in a draft too. The bar says *publishes together with …*, and both are reviewed, published and discarded together.
- **Two tabs or two people**: an edit made against an out-of-date view is refused with *This zone was changed in another tab…*. Reload and redo it.
- **Stale drafts**: if the published copy changed after the draft started (another import or a restore), Review says so and publishing is blocked. Discard and redo the change.

## Review

The **Review** tab shows:

- **Nodes**: each server serving the zone, and whether it has the published copy, is behind, was changed by hand (drift, on the primary), or can't be reached. A secondary's state comes from the serial it serves.
- **Changes**: records added, changed and removed
- **Also published**: linked zones (usually the reverse zone), with their own changes and checks
- `named-checkzone`'s verdict, and the file diff

**Discard draft** throws the pending changes away (including linked drafts).

## Publish

Above the **Publish** button, **Commit message** is prefilled with `Publish <zone>`. Change it to say what the change is for (`Add the new printer`). The new serial is added to it, and any reverse zone published along with it gets the same message. It's the version's title under **History**, and it's shown with the publish.

The button says where it goes: **Publish example.com to ns1 (ns2 will transfer it)**. It runs as a job with a live log:

1. Checks the primary is reachable and still has the file LiteBlox last wrote.
2. Sets the new serial and runs `named-checkzone`.
3. **Stages** the new file on the primary, which checks it with its own `named-checkzone`. If it refuses, nothing changes.
4. Commits the new version to the zone's history.
5. **Switches** the primary over (atomic file replace + `rndc reload <zone>`). If the reload fails, it restores its previous file.
6. Asks the primary over DNS which serial it serves, then waits up to 20 seconds for each secondary to transfer it.

If a step after 4 failed, or a secondary hasn't transferred the new serial in time (*hasn't transferred serial N yet*), the publish is marked **partial**. A slow secondary usually catches up by itself; otherwise fix the node, then **Republish to all nodes** on the Review page.

Without a primary picked yet, every node serving the zone holds its own copy and gets the publish: each one stages the file, and only when all have staged does any of them switch over.

Publishing waits while a [role change](/help/failover) (a promote, a demotion) is running.

## Drift: hand edits on the primary

If the zone file on the primary was changed outside LiteBlox, publishing stops before touching anything. Review shows that node as **changed on the node**, with a diff against LiteBlox's copy, and two choices:

- **Keep the node's edit**: the node's file becomes LiteBlox's published copy (any open draft then needs redoing)
- **Overwrite it on the next publish**: LiteBlox's copy wins; **Republish** to apply it

## History

**History** lists the zone's **publishes** (who, when, the result, the serial and the commit message; open one for each node's outcome) and every **version**: imports, publishes and restores, with author and time. Open one to see its diff. To see everything that changed between any two, tick them (two publishes, two versions, or one of each) and **Compare** in the bar at the bottom of the window: you get the record changes, the versions in between and the file diff, always older → newer. **Restore into a draft** (static zones) puts that version back as a draft (after confirming, if there's already one). Review it and publish as usual; it gets a fresh serial. A restore doesn't change PTRs in other zones.

## Read-only users

Readonly accounts see everything here but get no edit controls, and can't publish, discard or restore.
