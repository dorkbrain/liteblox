# Test environment

## LiteBlox container

```bash
./deploy/deploy.py --build                     # from the repo root
mkdir -p testenv/data testenv/backups
podman compose -f testenv/compose.yaml up -d
podman exec -it liteblox-test liteblox user add dev
# http://127.0.0.1:53530
testenv/reset.sh                               # stop and wipe data/ and backups/
```

`data/` and `backups/` are gitignored.

## Lab BIND nodes

End-to-end tests run against three VMs, each with snapshots to roll back to before re-testing:

| VM | Role | Starting state |
|---|---|---|
| **lab-ns1** | BIND + Kea node | minimal Debian 13, BIND not installed; a second NIC on an isolated bridge (the DHCP lab network, static address) |
| **lab-ns2** | BIND + Kea node | the same |
| **lab-client** | DHCP client | Ubuntu 24.04, a DHCP client on the isolated bridge, with `dig`, `nsupdate`, `tcpdump`, `nmap`, `dhcpdump` |

For the "existing server" case, give one node a BIND config of its own before its snapshot (repoint any `also-notify`, `allow-transfer`, `listen-on` and `primaries` from prod IPs to lab IPs first).

**DHCP in the lab:** Kea must only ever serve the isolated bridge. If the LAN the VMs share has a working DHCP server, run the dev server with `LITEBLOX_DEV_DHCP_NEVER_SERVE=<that LAN's network>`, and after each change check from lab-client that offers on the LAN still come only from the real server (`sudo nmap --script broadcast-dhcp-discover -e <LAN interface>`).

Before taking the snapshots:

- Create a sudo-capable user with SSH password login enabled. The bootstrap wizard uses it once.
- Install `python3`. The agent is stdlib-only, and bootstrap installs `python3-minimal` if it's missing.
- Firewall: allow from this workstation (and the LiteBlox host) TCP 22 (bootstrap), TCP 8530 (agent) and 53 TCP/UDP (`dig`); on the bridge, UDP 67 and TCP 8001 (the failover link) between the two nodes.
- Take the snapshot **before** any LiteBlox bootstrap, so "fresh node" can be restored.
