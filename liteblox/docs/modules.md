# Modules: what to run

LiteBlox is four modules. Run all of them, or only the ones you need:

| Module | Runs | Where |
|---|---|---|
| **DNS** | BIND9: zones, records, a primary and its secondaries, dynamic zones, TSIG keys | on your nodes |
| **DHCP** | Kea: subnets, pools, reservations, leases, a failover pair, DNS registration | on your nodes |
| **Time** | chrony: one list of time sources, nodes serving time to your network | on your nodes |
| **IPAM** | networks and ranges, every address used and free, devices seen, next free, sweeps | in LiteBlox itself |

Choose them under **Settings → Modules** (admins). A new install asks on its first Dashboard ("What will this LiteBlox run?"); an install upgraded from 3.x starts with all four on, so nothing changes until you switch one off.

## What switching off does

A module that's off is hidden everywhere: its menu entry and Settings tabs, its Dashboard tiles and columns, its problems on the status board, its part of [Search](/help/search), and its help pages (still readable, listed under "Not in use here"). Its pages and its [API](/help/api) calls answer **404**, saying the module is off. `GET /api/v1/status` lists the modules that are on.

Nothing is deleted. Switching a module back on brings its pages back as they were.

## What keeps a module on

A module that's in use can't be switched off, so nothing keeps running on your network unseen. Settings → Modules says what's using it:

| Module | In use while there is |
|---|---|
| DNS | a zone, or a node that runs BIND (scanners and DHCP/Time-only nodes don't count) |
| DHCP | a node with DHCP set up, or a DHCP subnet |
| Time | a node serving time |
| IPAM | never: it only reads, so it can always go |

Remove those first (DHCP → turn DHCP off on each node; the node page → Time → turn it off; Zones → delete). At least one module stays on.

## Common shapes

| You want | Modules |
|---|---|
| DNS, DHCP and time for a home or small office | all four (the default) |
| Only BIND, managed from a browser | DNS (IPAM is handy next to it: it reads your zones and leases) |
| A central address list and nothing on the network | IPAM only: add your networks and ranges, and name addresses with [IPAM records](/help/ipam#ipam-records), by hand or through the API; no nodes needed. Names from the DNS you already run come from [PTR lookups](/help/ipam#ptr-lookups-rdns) |
| DHCP, with the DNS you already run | DHCP (with IPAM if you like), and [DNS registration at another DNS server](/help/dhcp#registering-at-another-dns-server): Kea registers clients there. A DHCP node needs no BIND: untick **Runs DNS (BIND)** when you add it |
| A central address list that sees who's on each subnet | IPAM only, with a **scanner node** in each subnet ([below](#scanner-nodes)) |

## Getting started without DNS

**DHCP with the DNS you already run:**
1. [Install LiteBlox](/help/install) and create the first admin. On the Dashboard's "What will this LiteBlox run?", choose **DHCP** and **IPAM** (Time too, if you like).
2. Prepare the DHCP server like any node ([Nodes without BIND](/help/node-prep#nodes-without-bind)), then **Nodes → Add node** (no BIND box: with DNS off there's none) and **Set up** with **DHCP** ticked.
3. **DHCP → Settings → DNS registration → Another DNS server**: its address and a TSIG key it accepts updates with; **Test** checks them ([details](/help/dhcp#registering-at-another-dns-server)).
4. **DHCP → choose the interfaces**, then **Add subnet** with its pools and the **Domain** clients go in.
5. **IPAM → Add network** for the subnet. Its page shows the leases and reservations, what the DHCP node sees on the network, and (with Settings → IPAM → PTR lookups pointed at your DNS server) the names it holds.

**Only an address list:** choose **IPAM** alone, add your networks and ranges, and name addresses with IPAM records. To see who's on a network, add a scanner node in it (below).

## Scanner nodes

A node doesn't have to run BIND. When you add one, untick **Runs DNS (BIND)** (with the DNS module off there's no box: it never gets BIND). At setup, tick DHCP or Time for a DHCP- or Time-only node, or neither for a **scanner**: a small machine with just the LiteBlox agent on it. IPAM reads its neighbour table every minute (the devices it has talked to, with their MACs), sweeps the networks it is on (each network's IPAM settings → Sweep), and checks next free addresses through it. When a network has a scanner and a DNS or DHCP node, IPAM uses the scanner.

A scanner needs what any node needs (see [Preparing a node](/help/node-prep#nodes-without-bind)) but no BIND: Debian 12/13 or Ubuntu 22.04/24.04 with `python3` 3.9 or newer, systemd, SSH and `sudo` once for setup, then TCP 8530 open from LiteBlox. It has nothing to back up, so it isn't backed up.

From the command line: `liteblox node add scan1 192.168.5.10 --no-bind`, then `liteblox node bootstrap scan1 --ssh-user you`. `--no-bind` / `--bind` on `node bootstrap` change a node's choice while it serves no zones and isn't taken over.

## From the command line

```bash
docker compose exec liteblox liteblox modules                          # what's on, and what keeps each in use
docker compose exec liteblox liteblox modules --off dns dhcp ntp       # IPAM only
docker compose exec liteblox liteblox modules --save                   # keep the current choice; the Dashboard won't ask
```

Switching off is refused from the command line too while a module is in use. Changes are audited (Activity → "Changed the modules").
