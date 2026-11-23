# How LiteBlox works

LiteBlox runs your BIND servers for you. Give it a few Debian machines with a sudo account and it takes over their BIND configuration: zones, server options, ACLs and keys are all edited in the browser. One server is the **primary** for every zone and the others are its **secondaries**, so a change is made in one place and the rest copy it within seconds. On the same machines it can also run **Kea** for DHCP and **chrony** for time, and it keeps an address list (**IPAM**) of every network.

Each of these is a [module](/help/modules) you can switch off. LiteBlox can run DHCP only (registering clients at a DNS server you already have), or be just an address list, with no BIND anywhere.

## The pieces

| Piece | What it is |
|---|---|
| **LiteBlox** | This web app, running in a container. It keeps every zone's history in a git repository and everything else in a small database. |
| **Node** | A server LiteBlox manages: usually BIND, with Kea and chrony if you like. A node can also run without BIND (DHCP or time only), or just the agent, as a **scanner** that tells IPAM who is on its network ([Modules](/help/modules#scanner-nodes)). |
| **Agent** | `liteblox-agent`, a small Python service on each node (TCP 8530). LiteBlox talks only to it, over HTTPS where both sides prove who they are with certificates from LiteBlox's own certificate authority. |
| **Setup** | A one-off SSH login (with a password or key you provide, never stored) that installs BIND if needed, installs the agent and takes over the BIND configuration (on a node without BIND, only the agent, and Kea or chrony if chosen). SSH isn't used again until you repair or upgrade the agent. |
| **Kea** | The DHCP server LiteBlox can run on a node next to BIND, with a configuration LiteBlox writes: the interfaces it answers on, subnets, pools and options, all set on the DHCP tab. Two nodes can run it as a failover pair ([DHCP (Kea)](/help/dhcp)). |

```text
browser ──▶ LiteBlox container ──(mutual TLS, port 8530)──▶ agent on ns1 ─▶ BIND (primary)   ─▶ Kea (DHCP)
                │                                        └▶ agent on ns2 ─▶ BIND (secondary) ─▶ Kea (DHCP)
                ├─ zone history (git)
                └─ backups of each node        BIND: ns1 ──NOTIFY, IXFR──▶ ns2
                                               Kea:  ns1 ◀──failover (TLS, 8001)──▶ ns2
                                                     each Kea's D2 ──DNS updates──▶ the DNS primary
```

Kea is optional: a node runs only BIND until you set DHCP up on it.

**IPAM** lives in LiteBlox itself: it reads the zones, the leases and what the nodes see on the network, and adds names of its own ([IPAM](/help/ipam)).

## LiteBlox owns the whole BIND config

After setup, a node's `/etc/bind/named.conf` only includes files LiteBlox writes:

| File | Holds | Edited on |
|---|---|---|
| `/etc/bind/liteblox/options.conf` | `options { … }` for this node | the node's **Server settings** |
| `/etc/bind/liteblox/acls.conf` | named address lists, the same on every node | **Settings → ACLs** |
| `/etc/bind/liteblox/keys.conf` | TSIG keys, the same on every node | **Settings → TSIG keys** |
| `/etc/bind/liteblox/top.conf` | other top-level statements (logging…), and BIND's statistics channel on 127.0.0.1:8053, where the agent reads the query counts for the Dashboard | the node's **Server settings** |
| `/etc/bind/liteblox/zones.conf` | every zone the node serves | **Zones** |

The package's own root hints stay included as they were, and `rndc.key` stays the node's own. The node's original files are kept in `/etc/bind/pre-liteblox/`. A server that already has a configuration of its own can be [taken over](/help/existing-servers) too: LiteBlox imports it and proves its version is equivalent before switching.

Every configuration change works the same way: LiteBlox backs the node up, sends the new files, and the agent checks each file against a strict allow-list, runs `named-checkconf` on the whole set and switches over with `rndc reconfig`. Changes to more than one node go one node at a time, and LiteBlox checks after each that its zones still answer. If one stops answering, every node the change touched is rolled back.

If someone edits these files by hand, LiteBlox notices within a minute (**config drift**) and lets you overwrite the edit or keep it. See [Primary, failover and drift](/help/failover).

## One primary, the rest secondaries

**Make ns1 the primary** (on the **Nodes** page) gives ns1 the zone files and makes every other node its secondary. LiteBlox publishes to the primary only. The primary tells its secondaries (NOTIFY) and they fetch just the changes (IXFR), signed with a key LiteBlox creates for itself. If the primary fails, **Promote** a secondary; the old primary is demoted automatically when it comes back.

## Kinds of zones

| Kind | What it is |
|---|---|
| **Forward lookup** | names to addresses (`example.com`) |
| **Reverse lookup** | addresses to names, for one network (`192.168.0.0/24` → `0.168.192.in-addr.arpa`) |
| **Forwarding only** | a domain other servers answer: the nodes forward its queries there (`type forward`). No records, no primary. |

A forward or reverse zone is either:

- **static** (the default): you edit a draft, review it and publish it. LiteBlox writes the zone file.
- **dynamic**: DHCP servers, ACME clients and other programs with a key may change it with DNS updates (RFC 2136). Grid edits apply at once. See [Dynamic zones and TSIG keys](/help/dynamic).

## Changing a static zone

1. **Edit**: changes go into a **draft**, never straight to the servers. Changing an A/AAAA record can also change the matching PTR in a reverse zone; the two drafts are then linked.
2. **Review**: what changed, `named-checkzone`'s verdict, the file diff, and the state of every node.
3. **Publish**: LiteBlox:
    - checks the primary still has the file LiteBlox last wrote (if someone edited it by hand, that's **drift**, and you choose what to do)
    - bumps the serial above anything a node serves
    - stages the new file on the primary, which checks it with its own `named-checkzone`, then switches over (atomic file swap + `rndc reload`)
    - asks the primary, then each secondary, over DNS which serial it now serves

Every publish is a commit in the zone's **History**, with an optional message. Any two versions can be compared, and any version can be restored into a draft. See [Editing and publishing](/help/editing).

## DHCP

On a node with Kea, LiteBlox writes Kea's configuration the way it writes BIND's: the interfaces it answers on, the subnets with their pools, options and reservations, and DNS registration. Every change is previewed as a diff, checked on the node by `kea-dhcp4 -t`, applied one node at a time, and rolled back if Kea stops answering. Two nodes can share the work as a hot-standby failover pair, and clients' names can be registered in a dynamic zone, or at another DNS server ([DNS registration](/help/dhcp#registering-clients-in-dns)). Leases live in Kea; LiteBlox reads them live. See [DHCP (Kea)](/help/dhcp).

## Safety nets

- **Drafts and review**: nothing reaches a server without passing review.
- **Checked config changes**: every node is backed up first, the agent checks each file against its allow-list and `named-checkconf`, and a node that stops answering afterwards rolls everything back.
- **Drift detection**: hand edits to zone files and to the generated configuration are noticed, never silently overwritten.
- **History**: every published version of every zone, with who and when; dynamic zones get a version after each LiteBlox edit and a daily snapshot.
- **Backups**: each node's BIND configuration and zones (and Kea's configuration and leases), daily and before every configuration change. They restore with a plain `tar zxf … -C /`.
- **Re-adopt**: if LiteBlox's own data is lost, a new LiteBlox rebuilds it from the nodes ([Disaster recovery](/help/backups#disaster-recovery)).
- **Failover reports**: when a demoted primary held records the new one doesn't, LiteBlox keeps them for you to put back.

## Accounts

LiteBlox has its own accounts, separate from the servers' logins:

- **admin**: everything, including managing accounts on the **Users** page
- **readonly**: sees zones, nodes, settings, history, reviews and backup lists; can't change anything, download backups or view their contents

Roles apply to all of LiteBlox, not per zone. Every change, login and failed login is recorded in the audit log (**Users → Audit log**; sign-ins are hidden unless you ask for them). See the [Security model](/help/security).

## Bootstrap

Adding a node (or **Repair / upgrade agent** on its page) runs a bootstrap: one job, over SSH, with the setup account you give, which needs sudo. Its log is on the job's page. In order:

1. **Connect** over SSH, checking the node's host key against the one you pinned when you added it.
2. **Check the node:** its OS, sudo, Python 3.9 or newer and `iproute2` (installed with apt if missing), and on a BIND node, BIND itself (`bind9`, installed if missing) and `named-checkconf`.
3. **On a BIND node:** save a snapshot of `/etc/bind` to LiteBlox's backups ("pre-bootstrap"), and list the primary zones it serves.
4. **Create the agent's user**, `liteblox-agent` (a system user with no login shell), and on a BIND node add it to group `bind`. Let it send pings (for IPAM's probes).
5. **On a BIND node:** make the zone folders and files group `bind` and group-writable, so the agent can write them.
6. **DHCP, if you asked for it:** install Kea with apt (held back until LiteBlox's config is in place, so the package's sample config never runs), and write LiteBlox's config, which serves nothing until you set up a subnet.
7. **Time, if you asked for it:** install chrony with apt (it replaces `systemd-timesyncd`), and write LiteBlox's config, keeping the package's own aside.
8. **Install the agent:** issue its certificate from LiteBlox's own certificate authority, copy the agent to `/usr/local/lib/liteblox-agent/` and its config and certificates to `/etc/liteblox-agent/`, and start the `liteblox-agent` service.
9. **Check the agent** over mutual TLS (port 8530): its version, and on a BIND node rndc, the config check and whether every zone file is writable.
10. **Take over the BIND config**, if you asked for it on a fresh node ([Bringing in existing servers](/help/existing-servers)). Otherwise LiteBlox changes nothing in BIND until you take it over.

From then on LiteBlox talks only to the agent; the SSH password isn't kept. [Preparing a node](/help/node-prep#6-a-setup-account) says what the setup account needs, and [What LiteBlox's setup changes](/help/node-prep#9-what-litebloxs-setup-changes) has the detail of each step.
