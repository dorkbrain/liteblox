# Primary, failover and drift

One node is the **primary** for every forward and reverse zone; every other node LiteBlox has taken over is its **secondary**. LiteBlox publishes static zones to the primary, and dynamic updates go to it. The primary notifies its secondaries, and they transfer just the changes (IXFR), signed with LiteBlox's `liteblox-xfr` key. Forwarding-only zones have no primary: each node serving one forwards it by itself.

## Picking the primary

On **Nodes**, under **Primary and secondaries**, **Make ns1 the primary**. LiteBlox:

1. checks that every node involved is taken over and has a known DNS address, and that no zone has unresolved hand edits
2. writes the primary first: every zone, with LiteBlox's published copies of the static ones, and permission for its secondaries to transfer them
3. then each other node, whose zones become secondaries of the primary, checking that each one transfers every zone

A node that doesn't come up as a secondary is rolled back and listed, and the rest carry on. This is also how a dual-master pair from LiteBlox 1.x is converted, and how a node taken over later joins as a secondary (**Make ns1 the primary** again).

Each node's **DNS address** (on its page) is the address the other nodes use for transfers and NOTIFY, and that LiteBlox asks over DNS. It defaults to the address LiteBlox manages the node by; set it when the node answers DNS on another address.

## Promote: moving the primary

On a secondary's page, **Promote to primary** (or **Promote ns2** on the Nodes page, or `liteblox node promote ns2`). It works whether the old primary is up or down. The new primary needs to be reachable, and no publish may be running.

Where the new primary's zones come from:

- **static zones**: LiteBlox's published copy, so nothing is lost. If a node serves a higher serial (a copy changed outside LiteBlox), the serial is raised past it and committed as a new version, so every secondary still transfers.
- **dynamic zones**: the copy with the highest serial among the nodes LiteBlox can reach (the old primary's, if it's up). It reads them by zone transfer.

Then:

- **Old primary up:** it's demoted to a secondary in the same job. Anything that reached it during the switch is kept in a [report](#demote-reports).
- **Old primary down:** it's marked **demote pending** and demoted automatically when it answers again (see below). Any other node that's down is marked **update pending** and brought in line the same way.

LiteBlox's own DHCP (Kea) follows by itself: the same job points its DNS updates at the new primary (a DHCP node that's down catches up when the health check sees it). Other DHCP servers, ACME clients and scripts that send dynamic updates must be pointed at the new primary; LiteBlox doesn't change their configuration. LiteBlox doesn't promote by itself: someone has to click **Promote**.

Only one role change runs at a time, and publishing waits until it's finished.

## The health check

Every minute LiteBlox asks each node's agent how it is (the status and *last seen* on the Nodes page) and:

- for a node marked **pending** that answers again: runs its pending change as a job by `liteblox` (on the node's **Recent jobs**). If that fails, it's tried again after 10 minutes.
- for every other node: looks for [config drift](#config-drift)

Demoting a returning primary, or bringing a node in line:

1. its copies are compared with the primary's: dynamic zones by zone transfer, static zones it still holds as a primary from its file. Record sets only its copy has, or has differently, go into a demote report.
2. if its copy of a dynamic zone has a serial at or above the primary's, the primary's serial is raised past it, or the node would never transfer again
3. the node is backed up and rewritten as a secondary of the current primary, and every secondary zone is told to check the primary at once
4. LiteBlox checks it serves the primary's serials. A node that took its new config but hasn't finished transferring yet isn't a failure: the job ends **ok** with a ⚠ *still catching up* line, and the node transfers the zones on its own. The same goes for the other nodes after a **Promote**.

## Demote reports

When a node's copies held records the primary's didn't (updates a DHCP server sent to the old primary just before it failed, say), its page lists **Records only ns1's copies had**, and the Nodes page and dashboard show a *report* flag. A report shows each record set as it was on the node and as it is on the primary.

- Tick the record sets to keep and **Put back the ticked record sets**. For a dynamic zone they're sent to the primary as an update (guarded like a grid edit, so a record changed since then isn't overwritten). For a static zone they go into its draft, to review and publish.
- **Dismiss: nothing to put back** closes the report.
- **Download its copy** saves the node's whole copy of the zone as it was.

## Config drift

LiteBlox remembers what it last wrote to each node. When the health check finds that a generated file (`named.conf`, `options.conf`, `acls.conf`, `keys.conf`, `top.conf`, `zones.conf`) changed on the node, the node's page says **changed outside LiteBlox** and the Nodes page and dashboard show *config changed*. **See the changes** shows the diff (key secrets hidden):

- **Overwrite with LiteBlox's config** writes LiteBlox's files back, with the same backup, checks and rollback as any change.
- **Keep the node's change…** is offered when only `options.conf` or `top.conf` changed. It opens the node's [Server settings](/help/server-settings) filled in from the node's own files; **Review changes** and **Apply** make them LiteBlox's.

Changes to the other files can only be overwritten: ACLs, keys and zones are shared by every node or follow its role, so make the change in LiteBlox instead.

From the command line: `liteblox node drift NAME` shows the diff, `liteblox node overwrite NAME` writes LiteBlox's files back.

A newer LiteBlox sometimes writes a little more into these files (3.3 adds BIND's statistics channel to `top.conf`). That isn't drift: the health check notices that a node's config is behind and writes it again as a **bind config** job, with the usual backup, checks and rollback. It does so at most every 10 minutes, and only when no other job is running and the node has no changes made outside LiteBlox.

Hand edits to a static zone's file on the primary are a separate check, made before every publish; see [Editing and publishing](/help/editing#drift-hand-edits-on-the-primary).

### A second primary

If a node's `zones.conf` was changed by hand to make it a primary for zones it should be a secondary of, updates and edits would land on one primary and never reach the other. The node is flagged **second primary**, and its page offers a choice, with each node's serial for those zones:

- **Keep ns1 as the primary (overwrite ns2)**: LiteBlox's record of the primary, the usual choice
- **Make ns2 the primary**: a [promote](#promote-moving-the-primary)
