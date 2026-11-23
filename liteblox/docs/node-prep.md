# Preparing a node

A **node** is a server LiteBlox runs BIND on (or Kea, chrony, or only the agent: see [Nodes without BIND](#nodes-without-bind)). LiteBlox installs BIND if it's missing and writes its whole configuration, so all a node needs is a Debian machine with a fixed address and an account that can use `sudo`. x86-64 and 64-bit ARM both work: a Raspberry Pi 4 or 5 running Raspberry Pi OS Lite (64-bit), which is Debian 13, makes a fine node.

This page takes a fresh Debian 13 machine to the point where you can add it on the **Nodes** page, in about 15 minutes. For a server that already runs BIND with zones of its own, do steps 4–8, then see [Bringing in existing servers](/help/existing-servers).

> **In short:** static IP and hostname, a synced clock, `python3` and `sudo`, a sudo account that can log in over SSH, and firewall openings for DNS, SSH (during setup) and TCP 8530 from LiteBlox.

## 1. Install Debian 13

Use the netinst or minimal image. In the software selection, tick only **SSH server** and **standard system utilities** (no desktop).

Set the hostname you want the node to have (for example `ns1`) and a domain if you have one. You can change both later in step 3.

## 2. Give it a static IP

A DNS server needs a fixed address. With ifupdown (the Debian default), install `resolvconf` and edit `/etc/network/interfaces`, using your interface name (`ip -br link` shows it):

```bash
apt install -y resolvconf
```

```text
allow-hotplug ens18
iface ens18 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    dns-nameservers 1.1.1.1 1.0.0.1
```

Reboot (or `systemctl restart networking` from the console, not over SSH) and check:

```bash
ip -br addr
ping -c 2 deb.debian.org
```

Point `dns-nameservers` at an upstream resolver rather than at the node itself, so the node can still resolve names while BIND is being set up or is down.

Raspberry Pi OS uses NetworkManager instead of ifupdown. Set the address on its wired connection (`nmcli con show` lists the connection names; Raspberry Pi Imager's settings can also set the hostname, the user and SSH):

```bash
nmcli con modify "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.1.10/24 \
    ipv4.gateway 192.168.1.1 ipv4.dns "1.1.1.1 1.0.0.1"
nmcli con up "Wired connection 1"
```

## 3. Hostname

```bash
hostnamectl set-hostname ns1.example.lab
```

Then make sure `/etc/hosts` maps the node's own address to its name:

```text
192.168.1.10    ns1.example.lab ns1
```

## 4. Time sync

LiteBlox and the node authenticate each other with certificates, which need a correct clock. Signed zone transfers and DNS updates (DHCP's included) fail once two clocks are 5 minutes apart. LiteBlox checks each node's clock every minute and flags one that drifts (see [A node's clock is off](/help/troubleshooting#a-nodes-clock-is-off)).

```bash
timedatectl
```

You want `System clock synchronized: yes`. If not:

```bash
apt install -y systemd-timesyncd
timedatectl set-ntp true
```

Or let LiteBlox keep the time: once the node is set up, **Set up time sync** on its page installs chrony with the sources you choose ([Time (NTP)](/help/ntp)).

## 5. Packages

```bash
apt update
apt install -y bind9 bind9-utils bind9-dnsutils python3 sudo
```

`python3` (3.9 or newer; Debian 13 has 3.13) runs the LiteBlox agent, which needs nothing else installed. `python3` and `sudo` must be there before setup. BIND is optional: setup installs it when **Install BIND if it's missing** is ticked (the default).

## 6. A setup account

LiteBlox logs in once over SSH, as an account that can use `sudo`, to install BIND and its agent. The web wizard asks for that account's password; it's used for that one run and never stored.

```bash
adduser liteadmin
usermod -aG sudo liteadmin
```

Debian's SSH server accepts password logins for normal users by default (`PasswordAuthentication` in `/etc/ssh/sshd_config`). If you've turned that off, either turn it on for setup or set the node up from the command line with SSH keys (`liteblox node bootstrap NODE --ssh-user liteadmin --use-ssh-keys`).

After setup you can lock the account (`passwd -l liteadmin`). LiteBlox only needs it again to repair or upgrade the agent.

## 7. Firewall

Debian doesn't filter anything by default. If you use a firewall, the node needs:

| Port | From | Why |
|---|---|---|
| 53 UDP + TCP | your clients, the other nodes and the LiteBlox host | DNS; secondaries transfer zones from the primary over TCP 53, and LiteBlox checks serials and reads dynamic zones over DNS |
| 22 TCP | the LiteBlox host (and you) | setup over SSH; only needed during setup and upgrades |
| 8530 TCP | the LiteBlox host | the LiteBlox agent (mutual TLS) |
| 67 UDP | DHCP clients | only on a node that serves [DHCP](/help/dhcp) |
| 8001 TCP | the other node of a DHCP failover pair | the pair's link (mutual TLS), on the link addresses you pick |
| 123 UDP | the networks a node serves time to | only on a node that [serves time](/help/ntp#serving-time) |

An nftables example (`/etc/nftables.conf`). Replace the addresses, and keep a console open while you apply it so a mistake can't lock you out:

```text
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        meta l4proto { icmp, ipv6-icmp } accept
        udp dport 53 accept
        tcp dport 53 accept
        ip saddr 192.168.1.0/24 tcp dport 22 accept
        ip saddr 192.168.1.10 tcp dport 8530 accept    # the LiteBlox host
    }
}
```

```bash
apt install -y nftables
systemctl enable --now nftables
nft list ruleset
```

## 8. Pre-flight checklist

Run these on the node before adding it:

| Check | Command | Expect |
|---|---|---|
| Python | `python3 --version` | 3.9 or newer |
| sudo | `sudo -l -U liteadmin` | `(ALL : ALL) ALL` |
| Clock | `timedatectl` | `System clock synchronized: yes` |
| SSH host key | `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` | note the `SHA256:…` fingerprint |
| Reachable | from the LiteBlox host: `nc -vz NODE 22` | succeeded |
| BIND, if installed | `sudo named-checkconf && sudo rndc status` | no errors, `server is up and running` |

Keep the host key fingerprint handy. LiteBlox shows the fingerprint it receives when you add the node, and you should only confirm it if the two match.

## 9. What LiteBlox's setup changes

So nothing comes as a surprise, setup (from the node's page, **Set up**):

- saves a copy of `/etc/bind` to LiteBlox's backups before changing anything
- installs `bind9 bind9-utils bind9-dnsutils` if they're missing (when ticked)
- makes `/etc/bind` and your existing zone files group-writable for the `bind` group, so the agent can write them
- lets the `liteblox-agent` group ping without privileges, for IPAM's probes and sweeps, when the node's `net.ipv4.ping_group_range` leaves it out (Ubuntu's default does; Debian's covers every group): `/etc/sysctl.d/60-liteblox-agent-ping.conf`, which only widens the range
- creates a `liteblox-agent` system user in the `bind` group and installs the agent in `/usr/local/lib/liteblox-agent/`, its config and certificates in `/etc/liteblox-agent/`, and a `liteblox-agent` systemd service listening on TCP 8530
- **takes over the BIND configuration** (when ticked, the default) on a server with the stock Debian configuration: `named.conf` then includes only the files LiteBlox writes in `/etc/bind/liteblox/`, and `named.conf.options` and `named.conf.local` move to `/etc/bind/pre-liteblox/<time>/`. LiteBlox checks first that its version is equivalent to the stock one, and rolls back if BIND doesn't answer afterwards. A server with a configuration of its own is left as it is: [take it over](/help/existing-servers) from its page after reviewing the preview.

- **sets up Kea DHCP** only when **Set up Kea DHCP** is ticked: installs `kea-dhcp4-server kea-dhcp-ddns-server`, adds `liteblox-agent` to the `_kea` group, makes `/etc/kea` group-writable, and installs two small socket proxies so the agent can talk to Kea. Kea gets a configuration that serves nothing until you add a subnet. See [DHCP (Kea)](/help/dhcp).

Running setup again repairs or upgrades the agent and changes nothing that's already in place.

## Nodes without BIND

A node added with **Runs DNS (BIND)** unticked (a DHCP- or Time-only node, or a [scanner](/help/modules#scanner-nodes) for IPAM) skips everything about BIND: no `/etc/bind` snapshot, no BIND install, permissions or takeover, and the agent isn't in the `bind` group. It needs:

- Debian 12/13 or Ubuntu 22.04/24.04 with `python3` 3.9 or newer, systemd and `ip` (setup installs `iproute2` if it's missing)
- an account that can use `sudo`, over SSH, for setup (step 6)
- TCP 8530 open from LiteBlox (step 7); DNS doesn't need to be open
- a synced clock (step 4), unless LiteBlox sets up Time on it

Steps 1–3 apply as they are (a fixed address matters most: IPAM picks a node by the networks it is on).

## Next

Open **Nodes → Add node**, enter the node's address, compare the host key fingerprint with the one from step 8, then run **Set up** with the account from step 6. Server options such as recursion, forwarders and who may query are set afterwards on the node's [Server settings](/help/server-settings).
