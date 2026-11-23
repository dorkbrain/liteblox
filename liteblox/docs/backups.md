# Backups and restore

LiteBlox's zone history covers every zone's records, and its database holds each node's settings, ACLs and keys. **Node backups** are the files themselves, as BIND sees them on each server: the generated configuration, every zone file (dynamic zones and secondaries' copies included), the key files, and the server's original configuration in `/etc/bind/pre-liteblox/`. They're what you need to rebuild a dead server.

## What's in a backup

A `.tgz` of:

- everything under `/etc/bind`
- `/var/lib/bind/liteblox` (dynamic zones, secondaries' copies) and every other zone file BIND declares outside `/etc/bind`, apart from `.jnl` journals
- `var/lib/liteblox-agent/restored-backup/manifest.json` (node, time, BIND version, and a checksum of every file) and the output of `named-checkconf -p`

Files keep their owner, group and mode, and directories are included (so `/etc/bind` comes back as `root:bind` with its setgid bit).

Key files (`*.key`, `rndc.conf`, `bind.keys`, and the `keys.conf` LiteBlox writes with every TSIG key) are **included by default**, because a restore is useless without them. Untick **Include key files** on a node's Backups page if the backups folder isn't private.

## When backups happen

| Kind | When |
|---|---|
| scheduled | daily at `backup_at` (default 03:15, container time); **skipped when nothing changed** since the last backup (the list shows "unchanged at …") |
| manual | **Back up now** on a node's Backups page, or `liteblox backup run NODE` |
| pre-change | automatically before every configuration change LiteBlox makes: takeover, zones (create, add/remove node, settings, dynamic switch, delete), server settings, ACLs, keys, primary, promote and demotion |
| pre-bootstrap | over SSH, right before setup changes anything |

Publishing zone contents doesn't trigger a node backup: the zone history has every version, and the agent keeps the last 10 copies of each zone file in `/var/lib/liteblox-agent/backups/` on the node.

## Where they're kept

In the `./backups` folder of the LiteBlox host, one folder per node:

```text
backups/ns1/ns1-20261025-031500.tgz
backups/ns1/ns1-20261025-142217-manual.tgz
backups/ns1/ns1-20261024-203957-prebootstrap.tgz
```

Files are readable by the owner only. Point `./backups` at a NAS share if you want them off the host.

## Retention

Kept:

- the newest backup, always
- everything from the last 24 hours
- the newest scheduled or manual backup of each of the last **14 days** and **8 weeks** (`keep_daily`, `keep_weekly` in [settings](/help/reference#configtoml))
- pre-change and pre-bootstrap snapshots for **90 days**

Older ones are deleted after each backup run.

## Watching them

- The Nodes list marks a node **backup stale**, and the Dashboard lists it under Needs attention, when it hasn't had a successful backup in 48 hours.
- A node's **Backups** page can show one kind at a time (scheduled, manual, pre-change, pre-bootstrap). The Changes column still counts against the previous backup of any kind.
- Each backup's page lists its files and **what changed since the previous backup** (added, changed, removed).
- Admins can **Download** a backup or view any file in it.

## Restoring a node

On the server (or a fresh replacement prepared with [Preparing a node](/help/node-prep), steps 1–5):

```bash
tar zxf ns1-YYYYmmdd-HHMMSS.tgz -C /
named-checkconf -z
systemctl restart named
```

That puts back `/etc/bind` and any zone files elsewhere, with their owners and modes. The backup's manifest lands in `/var/lib/liteblox-agent/restored-backup/`.

Then in LiteBlox:

- **Same machine:** run **Repair / upgrade agent** on the node if the agent isn't running. If the restored configuration differs from what LiteBlox last wrote, the node is flagged *config changed* within a minute: **Overwrite with LiteBlox's config** ([Config drift](/help/failover#config-drift)). If a restored zone file on the primary is older than LiteBlox's copy, Review shows it as changed on the node; choose **Overwrite it on the next publish** and **Republish**. A restored secondary simply transfers its zones again.
- **Replacement machine:** it has a new SSH host key, which LiteBlox refuses until you [re-pin it](/help/troubleshooting#the-ssh-host-key-changed) with **Change address or host key** on the node's page (enter the new address there too if it has one). Then run **Repair / upgrade agent** to install the agent. Keep the existing node rather than removing and re-adding it, so its backups stay listed.

## Disaster recovery

Node backups bring back a server. If you lose **LiteBlox itself** (the host, or the `./data` volume), restore your copy of `./data` instead ([What to back up](/help/install#what-to-back-up)): it holds the database, the zone history, the certificate authority the agents trust, and the session key. With it, nothing is lost and the agents keep trusting LiteBlox.

### Without a copy of `./data`: re-adopt the nodes

The nodes keep running without LiteBlox, and each one holds what LiteBlox gave it: every key with its secret, the ACLs, its server settings, the zones with their grants and contents, which node is the primary, (with Kea) the subnets, reservations, the failover pair and where clients are registered in DNS (LiteBlox's own primary, or [another DNS server](/help/dhcp#registering-at-another-dns-server) with its key), and (with chrony) the time sources and which nodes serve time. Nodes without BIND (DHCP- or Time-only) come back the same way, from their Kea and chrony config. A new LiteBlox rebuilds its data from them:

1. Install LiteBlox again and create the first admin ([Installing](/help/install)).
2. **Nodes → Add node** for each of the old nodes, under its **old name** (a DHCP failover pair knows its nodes by name). A node that ran without BIND is added the same way, with **Runs DNS (BIND)** unticked.
3. **Set up / Repair** each one with the setup account. That gives its agent a certificate from the new LiteBlox's CA and changes nothing else; the job says the node's config came from another LiteBlox. Leave **DHCP** and **Time** unticked: a config a LiteBlox wrote is kept either way.
4. The Nodes page now offers **re-adopt them**. Tick every node the old LiteBlox managed (the primary and its secondaries, both nodes of a failover pair) and click **Preview**.
5. The preview lists what comes back, and checks each node: LiteBlox renders its config from the rebuilt data and compares every generated file, byte for byte, with the one on the node. Only when all of them match does **Re-adopt** appear.
   A node an older LiteBlox wrote lacks what newer versions add (3.3's BIND statistics channel and Kea's socket retries): the preview allows for exactly those and says the node was **written by an older LiteBlox: brought up to date after re-adopt**. The health check then writes it the current config, as after any upgrade (a failover pair's Kea gets it right away, with its new certificates).

The re-adopt changes nothing on the nodes, so DNS and DHCP keep serving throughout. There's one exception: a DHCP failover pair gets **new peer certificates** from the new CA (the old CA is gone, and the old private keys can't be read back). They're written to the standby first, then the primary, and the job waits until the pair is back in hot-standby. The primary keeps serving the whole time.

**What doesn't come back:**

- users, apart from the ones you create
- the audit log and old jobs
- each zone's history before the re-adopt (its current contents become the first version)
- drafts, and LiteBlox's list of node backups (the files stay in `./backups` and on the nodes)
- IPAM: networks, ranges, IPAM records, devices seen and their names
- comments on DHCP subnets and reservations, and zone preferences and notes that live only in LiteBlox (automatic PTRs, [zone notes](/help/editing#zone-notes))

The preview refuses, and records nothing, when:

- a generated file was **changed by hand** on the node, or differs in something more than what newer versions add. The diff shows what's different. Put the file back as LiteBlox wrote it (a node backup has it), or re-adopt without that node.
- **a node is missing**: the primary or a secondary that's still in the others' config, or one half of the failover pair. Add it and repair it too.
- this LiteBlox **isn't empty**: it already has zones, keys, ACLs, subnets or a managed node. Re-adopting only builds into a fresh LiteBlox.

**IPAM doesn't come back:** its networks, ranges and IPAM records live only in LiteBlox, so only a copy of `./data` has them. [Scanner nodes](/help/modules#scanner-nodes) hold nothing to rebuild: add them again and run **Set up / Repair**, and they work as before.

From the command line: `liteblox node readopt NAME…` shows the same preview and asks before going ahead.
