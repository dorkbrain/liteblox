> **LiteBlox now has its own site: [liteblox.dorkbrain.com](https://liteblox.dorkbrain.com)**. Features, screenshots, downloads, install steps and the full documentation all live there.
{.is-info}

This page is the build diary: why LiteBlox exists and how it got here.

## Inspiration

After working with DNS for many years professionally from editing raw BIND zone files, to using web interfaces on external hosting providers, DNS in AD, and most recently Infoblox, I wanted to have a good platform to manage my home networks.  It needed to be extremely lightweight and have a web UI that I found to be useful from an operator standpoint, and best of all 100% free.

The name LiteBlox comes from my desire for a lightweight Infoblox.  The Docker container running my home network uses less than 110MB of RAM on my Docker host, fulfilling the lightweight requirement.

LiteBlox is an independent project, not affiliated with or endorsed by Infoblox.

## The story so far

**4.7.2** (2026-11-23): **A Raspberry Pi as a node**
- LiteBlox already ran on a Pi as the web console; now the Pi is proven as a node too. I booted a Pi 4B from a USB stick with Raspberry Pi OS Lite (64-bit) and let LiteBlox set it up over SSH with a password, the same as any new server: BIND, Kea and chrony installed and running on ARM.
- To get it onto the lab's private DHCP network, the Proxmox bridge for that network now goes out to my switch as VLAN 100, and the Pi joins it on its one network port as a VLAN. That turned the lab network into a trunked one, still kept apart from the rest of my LAN.
- On the Pi: a DNS secondary taking zone transfers, time served to the lab, IPAM seeing devices, an agent upgrade over mutual TLS, and Kea in a failover pair with an x86 VM, both ways round. I stopped Kea on the Pi and the VM took over within a minute; started again, the Pi was back in charge 21 seconds later with every lease.
- The run found three things, fixed here: setup now waits long enough for the agent on a slow machine right after installing packages, the DHCP review no longer shows the DNS update key's secret, and a DHCP change on an interface made after Kea started (a new VLAN) now goes through instead of failing.
- **First available** on an IPAM network page jumps to the lowest address that is free and has no name in DNS, and highlights it.
- Next, 4.8: DHCP interface names per server (the Pi's VLAN had to be renamed to match the VM's), and a full Ubuntu Server node.

**4.7.1** (2026-11-23): **Add DNS from IPAM**
- I wanted to name a VM, `vm03`, in a static range, and IPAM only offered a DHCP reservation or an IPAM-only name, so I had to go to the zone's page for a real DNS record. Now every IPAM row with no name in DNS has **Add DNS…**: a name, a zone and a comment, and the A record and its PTR are added.
- The zone starts as the one most of the network's names already live in, and the name as whatever IPAM, a reservation or a lease already calls the address.
- In a static zone it publishes right away, or stays in the draft to look over on the zone's page first. In a dynamic zone (the one DHCP registers clients in) it goes out as a live update, so a setup with just one zone that takes DHCP names gets it too.
- A name typed in this way is safe from DHCP: reclaiming stale DHCP names never removes it, and Kea won't hand it to a client asking for the same name. I checked that in the lab with a client asking for exactly that name.
- My prod pulled this release from GitHub's registry; 4.6 came from my Forgejo, so both are proven.

**4.7.0** (2026-11-23): **Public on GitHub**
- LiteBlox is public at [github.com/dorkbrain/liteblox](https://github.com/dorkbrain/liteblox). Development stays in my own Forgejo; GitHub gets one commit per release, signed, with a release page holding the same downloads as the website.
- The image is on GitHub's container registry, `ghcr.io/dorkbrain/liteblox`, for x86-64 and ARM64. Installing or upgrading is now a version on the `image:` line and `docker compose pull`; the image files stay on the website for machines without a registry.
- Before anything leaves, the release step checks the source for my private host names and addresses and for files git doesn't track. On the very first run it caught two of my own tests that used a host name as a sample, so 4.7.0 went out without them.
- Nothing changed in the app itself.

**4.6.1** (2026-11-22): **ARM64, and a new home for the images**
- LiteBlox is now built for 64-bit ARM as well as x86-64, so a Raspberry Pi 4 or 5 with a 64-bit OS can run the web console. The image in the registry covers both, and docker pulls the right one by itself.
- The downloads now come as one image file per processor type, `-amd64` and `-arm64`. Both load under the same name, so the install steps don't change. `uname -m` tells you which one you need.
- Images are also tagged by minor and major version (`:4.6`, `:4`), so a compose file can follow the patch releases of one version.
- Behind the scenes, the images moved from a plain Docker registry to my Forgejo, beside the source. The arm64 build runs under emulation on an x86 workstation, and each image gets a smoke test before anything is pushed; the full test suite passed inside the arm64 image too. Nodes on ARM come later, after a lab run on an ARM VM.

**4.6.0** (2026-11-14): **Built-in HTTPS, if you want it**
- LiteBlox always needed a reverse proxy in front for HTTPS. Now it can do its own, the way security appliances do: turn it on under Settings → HTTPS and it listens on port 53443 beside plain HTTP on 53530, with a self-signed certificate made on the spot.
- A certificate of your own can be imported through the browser (PEM with its chain, or a .pfx), checked and previewed before it's used. Or your own Let's Encrypt tooling writes the files, and LiteBlox picks a renewal up within seconds, no restart. LiteBlox stays a utility, not a web server, so getting certificates is left to certbot or acme.sh; Help has a certbot example.
- HTTPS only turns plain HTTP into a page saying it isn't supported (no redirect), and `liteblox https allow-http` in the container is the way back if a certificate locks you out.
- Off by default: behind a proxy nothing changes. Mine stays behind Nginx Proxy Manager for now.

**4.5.0** (2026-11-14): **Agent upgrades without SSH**
- Upgrading a node's agent used to mean Repair over SSH with credentials every time. Now LiteBlox sends the new agent over the mutual TLS link it already has: one click per node, or Upgrade all agents on the Nodes page (or the API).
- The agent still never changes its own code. It saves what it was sent and restarts, and a small root installer checks it before putting it in place: the checksum, a real file owned by the agent (no links), no older versions, and it has to parse. A new agent that fails to start twice is swapped back for the old one.
- Only the agent's code changes this way; its service, certificates and config still change by Repair over SSH. Coming from 4.4 or earlier, each node needs one Repair to get the installer.
- The LiteBlox image now runs as uid 1000 even without a `user:` line.

**4.4.0** (2026-11-14): **Wi-Fi repeaters in IPAM**
- My Wi-Fi repeater answers on the network with one made-up MAC for itself and for every device connected through it, so IPAM kept warning that my reserved addresses had "another device" on them, and phones moving between the main Wi-Fi and the repeater looked like they were flapping. Now a MAC can be marked as a Wi-Fi repeater's on its device page, and IPAM stops counting it as flapping or as a conflict wherever it shows.
- Several names on one address are no longer flagged as something to check.

**4.3.0** (2026-11-13): **Export to CSV**
- Export CSV links in the web UI: every zone in one file from the Zones list, a DHCP subnet's addresses or every lease, an IPAM network's whole address table, and Devices seen.
- A zone's rows from the all-zones file import back through Add many unchanged. In the other files, a hostname that a spreadsheet would read as a formula gets a ' in front.

**4.2.0** (2026-11-12): **IPAM, after a week in prod**
- Devices on my network that hop between pool addresses had nearly every pool address marked as seen. Now a seen address with nothing else on it counts as in use for 24 hours by default (Settings → IPAM → Counts as in use for), while the history is still kept for the week, and next free still steers clear of anything seen in that week.
- The network list on the IPAM pages folds into a column of small squares, so the address table gets more room for its columns.

**4.1.1** (2026-11-08): **License and credits**
- LiteBlox is now released under the MIT License.
- The Subnet Calculator credits David C A Croft's Visual Subnet Calculator, of which it's an altered version, and ships its license.

**4.1.0** (2026-11-08): **Bulk record edits**
- Tick rows in a zone (the heading box selects every row the filter shows) to delete them, or give them one TTL or one comment, as one change to review and publish.
- **Add many**: paste zone-file lines or import a CSV, see what each line will do before anything is saved, then review and publish. A zone exports as CSV, and a CSV template comes with commented sample rows.
- **Move an address**: from Search (or an IPAM address row), give an address a new one everywhere at once: its names in every zone, its PTR, its DHCP reservation and its IPAM entry.
- **Stale DHCP names**: a dynamic zone lists the names DHCP left behind when a removal was lost, to delete them, or reclaims them hourly on its own (it holds back while DHCP isn't healthy, or when too many would go at once).
- The API takes up to 2000 record changes in one call, all or none.
- Dashboard: a pill for each service a node runs, and Recent activity without the hourly IPAM sweeps.

**4.0.0** (2026-11-07): **Modular installs**
- Settings → Modules: run DNS, DHCP, Time and IPAM in any mix, for example IPAM alone, or DHCP and IPAM next to the DNS server you already have. A new install asks which to run.
- Nodes without BIND: DHCP-only and time-only servers, and scanner nodes that only watch their networks for IPAM.
- IPAM without DNS: a name per address kept in IPAM, and PTR lookups at your resolver.
- DHCP registers clients in LiteBlox's DNS, at another DNS server (with a TSIG key and a Test button), or not at all.
- Re-adopt (rebuilding LiteBlox's data from its nodes) covers nodes without BIND too.

**3.5.0** (2026-11-07): **Tools**
- A **Tools** menu in the top bar: a Subnet Reference (every prefix from /0 to /32 with its mask, usable hosts and where the next network starts) and a visual Subnet Calculator (divide and join a network, exclude parts of it, bookmark the layout, copy it as text). Each opens in a new tab.
- A light/dark button by your username: Auto (follows your system), Light or Dark, remembered per browser.

**3.4.0** (2026-11-07): **IPAM**
- Networks and ranges, each with an address map, a usage donut and one table of every address, used and free, with a comment saved where it belongs (the DNS record, the reservation, or a note).
- Devices seen: what the servers see on the network, with vendor names and labels; an address that keeps changing MAC shows up in Needs attention.
- Name-only DHCP reservations: a fixed name in DNS for a device without fixing its address.
- Next free addresses from the API, and `lbcli.py`, a one-file command-line client to reserve and release them.
- An optional sweep that pings a network now and then to find quiet devices.

**3.3.4** (2026-11-06)
- Windows clients get their name registered in DNS, not just the PTR.
- The DHCP Addresses table sorts by any column and counts declined addresses.
- Missing DNS grants are added in place from a subnet's Review.

**3.3.3** (2026-11-02)
- A DHCP subnet can be prepared before it's served, so moving DHCP over from your router is one change.

**3.3.2** (2026-11-01)
- Search across every zone and DHCP, by name, address, network or MAC.

**3.3** (2026-11-01): the Dashboard, a Jobs page and a pass over every page.
**3.2:** time sync with chrony.
**3.1:** the REST API
**3.0:** Kea DHCP with failover.

Every release, in full: [the changelog](https://liteblox.dorkbrain.com/changelog/).
