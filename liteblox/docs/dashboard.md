# The Dashboard

The Dashboard shows what LiteBlox knows about your servers right now, and what needs you. Everything on it comes from LiteBlox's own database, which the [health check](/help/failover#the-health-check) refreshes every minute: it asks each node how it is, compares its config with what LiteBlox wrote, reads its clock, and records a few figures for the graphs. The page reloads itself every minute while it's open (not while its tab is hidden). Times such as *5 min ago* (here and for "last seen", "last login" and the like across LiteBlox) show the full local time when you point at them; history and the audit log keep full times.

## Getting started

Until a node is set up, taken over and has a primary and zones, the Dashboard lists those steps in order, each linking to the page that does it. DHCP and time sync are optional steps at the end. Once nodes exist, the list moves into a **Setup** card beside the rest until the DNS steps are done.

## The tiles

| Tile | Shows | Turns amber or red when |
|---|---|---|
| **Nodes** | nodes ready out of all of them, and which is the primary | a node doesn't answer, isn't set up, has a stale backup or an agent certificate close to expiry |
| **DNS zones** | how many zones, and unpublished drafts | a publish failed, a node's BIND config changed outside LiteBlox, a demotion is pending or left reports, a [reclaim pass held back](/help/dynamic#reclaiming-them-on-a-schedule), or there's no primary |
| **DHCP leases** | active leases, how many of the pools' addresses are taken (leased or declined), the failover pair's state | the pair isn't hot-standby, Kea isn't running or listening on a node, a Kea config changed on a node, or a subnet's DNS key lacks grants |
| **Time** | how many nodes chrony keeps in sync, and the largest offset | chrony isn't running or has no source, or a clock is 30 s or more from LiteBlox's |
| **Attention** | how many problems need you | any of the above |

The top bar's **Dashboard** link carries the same colour as a dot on every page: green when nothing needs you, amber for warnings, red for errors.

The button beside your username at the top right switches the colours between **Auto** (follow the system's light or dark setting, the default), **Light** and **Dark**. The choice is kept per browser, not per account, and applies to every page, the sign-in page and the API page included.

## Needs attention

Each problem says what's wrong and links to the page that fixes it. **error** (red) means something is broken now, like a node not answering or DHCP failover stopped; **check** (amber) means something is off and needs a look, like a config edited on a node or a backup that's two days old; **note** is information that needs nothing from you, like an unpublished draft or a config the health check is writing again by itself. Notes don't change the colour.

## Services

One row per node (hover over its name for its address):

- **Role**: a pill for each service it runs: **DNS**, **DHCP**, **NTP**, and **IPAM** on a node that IPAM sweeps and checks a network from (the one picked for the network, else the first node on it). A node running none of them shows *agent only*.
- **DNS**: its role, **primary** or **secondary** (hover for how many zones it holds), or *not taken over* yet.
- **DHCP**: its role in the failover pair, **primary** or **standby**, or **serving** when it runs alone. While all is well the pill is green, or plain for the standby (as for a DNS secondary). It turns amber for a pair in *partner-down* or Kea still trying to listen, and red for *terminated* or Kea not running; hover for the state.

The other columns are its status, its time offset (chrony's, or its clock's distance from LiteBlox's when LiteBlox doesn't run chrony there), its last good backup, and its agent version. A node that doesn't answer shows dashes rather than what it last reported (its DHCP pill goes grey, *unknown*), and the tiles leave it out. **upgrade** means this LiteBlox carries a newer agent: **Upgrade agent** on the node's page installs it ([Upgrading an agent](/help/install#upgrading-an-agent)).

The last columns are the node's load average, memory and disk use (of `/`), and a graph of the DNS queries it answered per minute over the last day. The agent reads the query counts from BIND's statistics channel, which LiteBlox adds to each node's `top.conf` on `127.0.0.1:8053` (see [Security](/help/security)).

## DHCP pools

For each subnet: how many of its pool addresses are taken (leased, or *declined*: a client said the address was already in use, so Kea holds it back for a while), as a bar (amber from 80 %, red from 95 %), active leases outside the pools (reserved addresses outside them, usually), the number of reservations, and a graph of active leases over the last day. The figures come from the health check, which reads the leases from the failover primary each minute, or from the standby when the primary doesn't answer. If neither answers, it records nothing rather than a false zero.

## Recent activity

The last jobs (with their status, linking to their logs) and changes from the audit log, newest first. Logins are left out. A change a job made shows as the job. Scheduled jobs, such as the hourly [IPAM sweeps](/help/ipam#the-sweep), show only when they fail; the ones LiteBlox starts to fix something (user `liteblox`) always show. **All jobs** opens the [Jobs page](/help/troubleshooting#where-to-look), **Audit log** the full log.

## History

The figures behind the graphs are kept per minute for two days, then as 15-minute averages for 30 days. Removing a node or a subnet removes its figures.

## For monitoring

`GET /api/v1/status` returns the tiles and the problems, with an overall `level` of `ok`, `warn` or `error`. See [The API](/help/api#status).
