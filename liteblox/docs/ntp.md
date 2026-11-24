# Time (NTP)

Clocks matter to LiteBlox more than they might seem:
- signed zone transfers and DNS updates (DHCP's, ACME's, LiteBlox's own) fail once two clocks are 5 minutes apart (`BADTIME`)
- a DHCP failover pair stops at about a minute apart
- the agents' certificates are refused by a clock that's far off

LiteBlox can keep the nodes' time itself. It runs **chrony** on each node you set up, with one list of sources for every node, and writes chrony's whole configuration the way it writes BIND's and Kea's.

## Setting it up on a node

On the node's page, the **Time (chrony)** card has **Set up time sync**. It opens the **Repair / upgrade agent** form with **Set up time sync** ticked; the CLI equivalent is `liteblox node bootstrap NAME --ntp`. Over SSH, setup:

1. installs `chrony`. It replaces `systemd-timesyncd`, Debian's default, which can only sync, not serve.
2. copies the package's `chrony.conf` to `/etc/chrony/pre-liteblox/<time>/` and writes LiteBlox's, with the sources from **Settings → Time** (Debian's own pool until you set your own)
3. lets the agent write `/etc/chrony` (group-writable for it), and installs a small systemd path unit, `liteblox-chrony.path`, which restarts chrony whenever LiteBlox replaces its config. That way the agent never needs root.

Running setup again checks all this and keeps the configuration LiteBlox wrote. **Repair / upgrade agent** without the box keeps it too. A node you don't set up keeps its own time sync; the clock check still watches it.

## Sources

**Settings → Time** holds the servers every node syncs from, one per line:

```text
pool 2.debian.pool.ntp.org
server 192.168.1.1 prefer
server time.example.com nts
```

- `pool NAME`: a name with several servers behind it (chrony uses up to four of them)
- `server ADDRESS`: one server, by name or address. A line with just an address is a server too.
- Options: `prefer` (use it when it's good), `nts` (authenticated time, when the server offers NTS), `minpoll N` / `maxpoll N` (how often to ask, as powers of two seconds), `noiburst` (`iburst`, a quick first sync after a restart, is on by default)

Several sources are better than one: chrony compares them and ignores one that's wrong.

**Review** shows each time server's new `chrony.conf`, and chrony's own check of it on the node (`chronyd -p`). **Apply** changes the nodes one at a time:
1. back the node up
2. write the new file, which restarts chrony
3. check that chrony runs again

If it doesn't, every node the change touched gets its previous file back, and so does the list here. A source that isn't reachable yet doesn't stop the change: a pool takes a moment, and the card shows it once chrony has found it.

## The Time card

| Line | Meaning |
|---|---|
| **chrony** | running, or not |
| **Synced from** | the source chrony follows now, its stratum (how many steps from a reference clock), and this node's offset from it |
| **Sources** | each one: *in use*, *combined* (used to check the one in use), *reachable*, or *not reachable* |

**Rewrite time config** writes LiteBlox's configuration again.

The Nodes page and the Dashboard flag a node whose chrony has **no usable source** (*time: no source*), or isn't running (*time: chrony down*), or whose config was edited by hand (*time config changed*).

## Changes made on the node

Every minute the health check compares `chrony.conf` with what LiteBlox wrote. An edit on the node shows as **changed outside LiteBlox** on the card, with the differences, and **Overwrite the changes** writes LiteBlox's version back. A node that was down when the sources changed gets the new file when the health check next sees it (*config behind* until then).

## Serving time

A node set up for time sync can answer other machines' time requests too: workstations, printers, cameras, anything that speaks NTP. With two such nodes, your network keeps one consistent time even when the internet is down.

On **Settings → Time**, under **Serving time**, for each node:

- **Serves time**, **to networks**: the networks it answers, one per line (`192.168.0.0/24`, or an IPv6 prefix like `fd00:1:2:100::/64`). Name them; serving every address isn't allowed. The review notes a network the node has no address in, since nobody there could reach it.
- **Keep serving when the sources are unreachable**: chrony goes on answering from its own clock (as stratum 10) instead of going quiet. With two serving nodes they agree among themselves (chrony's *orphan* mode), so clients don't see two different times.

The same **Review** and **Apply** as for the sources. Then open **UDP 123** on the node for those networks ([firewall](/help/node-prep#7-firewall)).

**Handing it out by DHCP:** on a DHCP subnet's page, the **NTP servers** field suggests the serving nodes' addresses in that subnet. Saving the subnet with them sends them to clients as option 42 (`ntp-servers`). Most systems use it: `systemd-timesyncd` and NetworkManager do, and Windows takes it when it's set to sync with NTP.

**Over IPv6:** a node serves time over IPv6 to the IPv6 prefixes listed for it, from its static address in each. A [DHCPv6 subnet](/help/ipv6#dhcpv6-subnets)'s **NTP servers** field suggests those addresses the same way, sent as option 31 (`sntp-servers`).
