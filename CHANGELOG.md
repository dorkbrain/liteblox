# Changelog

## 4.7.0 — 2026-11-23

- GitHub: LiteBlox is public at github.com/dorkbrain/liteblox, one signed commit per release, and every release has a release page there with the downloads
- Images on GitHub's container registry: ghcr.io/dorkbrain/liteblox, for x86-64 and ARM64, so installing and upgrading is docker compose pull; the image files on the website stay for hosts without a registry
- Help: Installing and upgrading starts from ghcr.io, with a section for hosts without a registry; the website header links to GitHub
- No app or database changes; no agent upgrade needed


## 4.6.1 — 2026-11-22

- Images: LiteBlox is built for ARM64 as well as x86-64, so a Raspberry Pi 4 or 5 with a 64-bit OS (or another 64-bit ARM board) can run it; the registry image covers both, and docker pulls the right one
- Downloads: one image file per processor type, liteblox-image-vX.Y.Z-amd64.tar.gz and -arm64.tar.gz; both load as localhost/liteblox:X.Y.Z, so the install steps are the same (uname -m tells you which: x86_64 or aarch64)
- Images are now tagged :X.Y.Z, :X.Y, :X and :latest, so a compose file can follow patch releases of one version
- No app or database changes; no agent upgrade needed


## 4.6.0 — 2026-11-14

- HTTPS: LiteBlox can serve HTTPS itself, opt-in under Settings → HTTPS (admins): port 53443 beside plain HTTP on 53530, which always listens; publish the port in docker-compose.yaml ("53443:53443") to use it
- HTTPS: a self-signed certificate made on the tab (ECDSA, 825 days, for the names and addresses you give; not signed by the agents' CA), or one imported through the browser (PEM with its chain and key, an encrypted key, or a .pfx/.p12), checked and previewed before it's used
- HTTPS: the files in ./data/tls (cert.pem, key.pem) are picked up within seconds with no restart, so certbot or acme.sh can keep them renewed (Help has a certbot DNS-01 example); a pair that doesn't load keeps the previous one serving, and the tab and the Dashboard say why
- HTTPS: HTTPS only makes plain HTTP answer every page with a note that HTTP isn't supported (no redirect; /healthz still answers); it can only be turned on over HTTPS, and docker compose exec liteblox liteblox https allow-http turns it off again
- CLI: liteblox https status, allow-http, off, on, regenerate; liteblox serve --https-port (or LITEBLOX_HTTPS_PORT)
- Logins: a session cookie per scheme (__Host-liteblox_session, Secure, over HTTPS), so logging in over HTTP and HTTPS both work; you log in once on each
- Dashboard: problems for an HTTPS certificate that has expired, expires within 30 days, or doesn't load
- lbcli: --ca FILE (or LITEBLOX_CA) trusts a downloaded certificate instead of --insecure
- Help: a new HTTPS page; How LiteBlox works now lists what bootstrapping a node does, in order
- Schema v40: the update migrates the database; no agent upgrade needed


## 4.5.0 — 2026-11-14

- Nodes: Upgrade agent on a node's page (and Upgrade all agents on Nodes) sends this LiteBlox's agent to the node over mutual TLS, no SSH needed; one node at a time, as a job, audited
- Nodes: the agent only saves the new code and restarts; a small root installer on the node checks it before putting it in place (its SHA-256, a regular file owned by the agent with no links, at most 2 MB, not an older version, parses as Python) and keeps the old one
- Nodes: a new agent that doesn't start twice is swapped back for the old one, and the job says why; anything refused leaves the installed agent running
- Nodes: only the agent's code changes this way; its service, the installer, config and certificates still change by Repair / upgrade agent over SSH
- API: POST /api/v1/nodes/{name}/upgrade-agent (an admin's full token) runs the same job; nodes carry install_rev and can_upgrade
- Image: runs as uid 1000 by default (USER 1000:1000), as docker-compose.yaml always did; a user: line still overrides it
- Upgrading from 4.4 or earlier: run Repair / upgrade agent once on every node to put the installer in place; later agent upgrades are one click
- Schema v39: the update migrates the database


## 4.4.0 — 2026-11-14

- IPAM: a MAC can be marked as a Wi-Fi repeater's on its device page (repeaters that translate MACs show one MAC of their own for every device connected through them); a change to or from it isn't flapping, it raises no "reserved for" or "IPAM has it for" warning, and saving a reservation doesn't warn about it; seen addresses still count as in use
- IPAM: Devices seen marks repeater MACs (and finds them with "repeater"), the line under a MAC says Wi-Fi repeater, and the API (repeater on devices and seen entries) and the Devices seen CSV carry it
- IPAM: several names on one address are no longer a check
- Zones: the SOA help for Primary nameserver and Refresh describes the primary and its secondaries instead of dual masters
- Schema v38: the update migrates the database; no agent upgrade needed


## 4.3.0 — 2026-11-13

- Zones: Export CSV on the Zones list puts every zone (or the kind the filter shows) in one file, with a zone column and the same columns as one zone's export; dynamic zones are read from their primary, and a zone that can't be read is left out with a # line saying why
- Zones: a zone's rows from that file import back through Add many unchanged; the zone page's link is now Export CSV
- DHCP: Export CSV on a subnet's Addresses tab and on Leases (every subnet, and leases outside them): state, MAC, hostname, reservation, lease state, expiry in local time, node, in pool, DNS zone; leases are read live from Kea, and a node that can't be read gets a # line
- IPAM: Export CSV on a network page covers every page of its address table (Used only follows the switch; networks bigger than a /16 export used addresses only), with the API's columns; Devices seen exports what its filter shows
- CSV: in the DHCP and IPAM files a cell starting with = + - or @ gets a leading ' so a spreadsheet doesn't run it as a formula; zone exports stay exact
- Read-only users can export too
- No schema or agent change: no agent upgrade needed


## 4.2.0 — 2026-11-12

- IPAM: Settings → IPAM → Counts as in use for (24 hours by default): a seen address with nothing else on it (no name, lease or reservation) counts as used on the network pages, the map and the used counts only this long; Keep for stays how long it is kept, and next free still passes over anything seen within Keep for
- IPAM: past that window an address shows as free, with its MAC and when it was last seen
- IPAM: the network list folds to a column of squares (usage as the fill, the network in the tooltip), remembered per browser; phones are unchanged
- Help: Installing and upgrading loads the downloaded image instead of pulling from a registry
- Schema v37: the update migrates the database; no agent upgrade needed


## 4.1.1 — 2026-11-08

- License: LiteBlox is now released under the MIT License, Copyright (c) 2026 Dorkbrain; the LICENSE file is in the source and the image
- Subnet Calculator: credits David C A Croft's Visual Subnet Calculator, of which it is an altered version, on its page and in Help, and ships its license
- License notices for the vendored htmx and Alpine.js
- The agent file changed (a license comment only, no change in behaviour), so the Nodes page marks each node upgrade: Repair / upgrade agent clears it


## 4.1.0 — 2026-11-08

- Zones: tick rows in the record grid (the heading box selects every row shown after the filter) to Delete them, Set TTL or Set comment at once, as one change to the draft with their PTRs; in a dynamic zone, Delete as one update
- Zones: Add many: paste zone-file lines or import a CSV, preview what each line adds, skips or gets wrong, optionally replace records of the same name and type, then review and publish as one change; CSV export of a zone, and a CSV template with commented sample rows
- API: POST /api/v1/zones/{zone}/records/batch makes up to 2000 adds, changes and deletes as one change, all or none (a 422 lists every bad op); one update in a dynamic zone
- Move an address: Move to… on Search's address card (and Move… on IPAM address rows) moves its A records in every static zone, its PTR, its DHCP reservation and what IPAM keeps for it to a new address, with a preview and one review and publish
- Stale DHCP names: a dynamic zone's Stale names lists the names Kea registered and left behind (no lease or reservation, the last lease ended longer ago than the reclaim time); delete them with their PTRs, or let the zone reclaim them hourly (Settings → Stale DHCP names), held back while DHCP isn't healthy or when more than a quarter would go at once
- Dashboard: Services shows a pill per service each node runs (DNS, DHCP, NTP, IPAM), DNS and DHCP role pills coloured by health, and the node name alone (its address on hover)
- Dashboard: Recent activity leaves out scheduled jobs (the hourly IPAM sweeps) unless they fail
- Times in Needs attention and the CLI's node and token lists are local time, not UTC
- Schema v36: the update migrates the database; no agent upgrade needed


## 4.0.0 — 2026-11-07

- Modules: Settings → Modules turns DNS, DHCP, Time and IPAM on or off, so LiteBlox can run any mix of them (IPAM only, DHCP + IPAM next to another DNS server, …); a new install asks which to run, and menus, the Dashboard, Search, Help and the API follow the choice
- Nodes without BIND: DHCP-only and time-only nodes, and scanner nodes (no BIND, Kea or chrony) that only watch their networks for IPAM (devices seen, next free, sweeps); Add node has a Runs DNS (BIND) box, the CLI --no-bind
- IPAM without DNS: a name per address kept in IPAM (IPAM records), and names looked up as PTRs at the resolver
- DHCP: clients are registered in LiteBlox's DNS, at another DNS server (its address, port and a TSIG key, with a Test button that checks each zone), or not at all; with another server each subnet gets a domain and, if needed, its own reverse zones
- Re-adopt rebuilds nodes without BIND too: DHCP-only and time-only nodes, and DNS registration at another server (scanners and IPAM still need a copy of ./data)
- Upgrades: skipping versions is fine; an older image now refuses to start on a database a newer LiteBlox wrote, instead of running on it
- Docs: a Modules page (what to run, getting started without DNS), Preparing a node, Upgrading to 4.0 (Repair / upgrade agent on each node)


## 3.5.0 — 2026-11-07

- Tools menu in the top bar: Subnet Reference (/0 to /32: mask, usable hosts with /31 = 2 and /32 = 1, and where the next network starts) and Subnet Calculator (divide and join a network, exclusions, a bookmarkable layout, copy as text), each opening in a new tab
- A light/dark button by your username: Auto (follows the system), Light or Dark, remembered per browser and applied before the page draws, on the login and API pages too
- Top bar: at tablet widths the links wrap onto a second row instead of splitting names over two lines


## 3.4.0 — 2026-11-07

- IPAM: networks and ranges (added by hand, or in one click for each DHCP subnet and reverse zone not yet covered), nested by prefix so a /16 per site holds its networks
- IPAM: a network's page with an address map, a utilization donut and every address, used and free, in one table: names, reservation, lease, MAC and vendor, last seen, and checks that flag what doesn't agree
- IPAM: one comment per address, saved where it lives: on the A record (a draft), on the reservation, or as an IPAM note
- IPAM: Devices seen: each node's neighbour (ARP) table is read every minute and kept for 7 days; an address that keeps changing MAC is flagged in Needs attention (Acknowledge it, or mark its MACs as expected)
- IPAM: MAC vendors from the IEEE list, refreshed weekly
- IPAM: devices: a label and a comment per MAC, shown wherever the MAC is; Register a name, Fix its address and Back down from a device's page
- DHCP: name-only reservations: a hostname for a MAC with no fixed address, in a subnet that registers clients in DNS
- IPAM: next free addresses, one or a block of up to 64, checked on the network with a ping and ARP from a node there and held for a few minutes
- API: all of IPAM, plus assign and unassign (A + PTR records, or DHCP reservations by MAC) with groups, so a lab can be named in one call and torn down in another
- lbcli.py: a one-file command-line client (Python 3.9+, nothing to install) for next free, reserve, unassign, release and show, downloadable from the API token page
- IPAM: an optional sweep per network (hourly, daily, or Sweep now) pings every address to find quiet devices
- Agent: /neigh and /probe (it pings only the node's own networks); the Repair / upgrade page says what each option will do on that node
- Downloads: each release also comes as a gzipped image tarball, with .sha256.txt checksums for both tarballs


## 3.3.4 — 2026-11-06

- DHCP: clients that ask to update their own name (Windows, option 81) are registered anyway: Kea now writes their A record as well as the PTR (ddns-override-client-update); an Extra subnet setting for it is no longer needed
- DHCP: Review's "Add the missing grants" adds them in place, shows the job's log under the button, then reviews the form again
- DHCP: a subnet's Review no longer shows its reservations being removed (they were kept on save, but the review and its kea-dhcp4 -t check left them out)
- DHCP: the job log says the failover pair can take a minute or two to reach hot-standby
- DHCP: the Addresses tab and the Leases page count "N active · M declined · R reservations"; declined addresses (no MAC) are marked
- DHCP: the Addresses table sorts by any column (IP by default, numerically)
- Dashboard: pool use counts declined addresses as taken; the DHCP tile says "no subnet served yet" or "no lease counts yet" instead of "no pool figures yet"
- Docs: a reverse proxy on the same docker host reaches LiteBlox from the docker network's gateway: list it in FORWARDED_ALLOW_IPS
- Removed: liteblox import-v1 and the zoneedit v1 import docs (taking over an existing BIND server stays)


## 3.3.3 — 2026-11-02

- A DHCP subnet can be added before its interface is served: it's saved "not served" (marked on the DHCP tab, the subnet page and the Dashboard), and Kea answers for it once you tick the interface, so switching from another DHCP server is one change
- A DHCP change that leaves a node's Kea config as it is no longer touches the node (no reload, no failover resync): reservations in a subnet that isn't served yet take seconds
- Ticking an interface's review lists the subnets Kea starts answering for; the DHCP help has a "Moving DHCP over from your router" section
- Promote and reconcile read zone files with CRLF line endings (zoneedit v1's), so records only on the old primary are kept
- Set up waits while another apt run (Debian's daily update) holds its lock, instead of failing
- import-v1 dates old versions in History by when v1 saved them


## 3.3.2 — 2026-11-01

- Search across every zone and DHCP: a top-bar box (press /) and a Search page, by name, IPv4 address, network or MAC (whole or partial)
- Static zones are searched in their draft; dynamic zones live from their primary, or from their last saved version when it's down
- Searching one address shows its names, PTR, reservation, lease and subnet, and flags what doesn't agree (no PTR, a PTR to another name, a reservation held by another MAC, a lease name not in DNS, a static name inside a pool)
- Results open their zone or subnet with the filter already set (?filter= on the zone grid and the Addresses tab)
- GET /api/v1/search returns the same, with the address view for an IP


## 3.3.1 — 2026-11-01

- Every static zone is kept sorted: records in DNS order on every save, with no per-zone setting (Add below and import-v1 --sort are gone); zones that weren't sorted yet, and imported ones, get a "put in sorted order" draft to review
- Zone notes, kept in LiteBlox only (Settings tab, a card above the records, PUT /api/v1/zones/{zone}/notes); comment lines on their own move from the zone file into the notes when a sorted draft is published
- $GENERATE lines stay as a block after the records; a zone that can't be sorted ($INCLUDE, say) keeps its own order and is flagged on the Raw tab and the Dashboard
- Kea that gave up opening its sockets is reloaded by the health check once its interfaces are up
- Re-adopt accepts nodes an older LiteBlox wrote, and the health check brings them up to date
- Failed logins are throttled (5 per account, 20 per address, over 15 minutes); logins record the client's address
- The Zones list shows each zone's kind and filters by it; a node's Backups page filters by kind


## 3.3.0 — 2026-11-01

- A Dashboard that shows what needs you: tiles for nodes, zones, DHCP leases and time, a Needs attention list with a link to each fix, a row per node (roles, offsets, backup, agent, load, memory, disk, a 24-hour DNS query graph), DHCP pool use with lease graphs, recent activity and quick actions; a first-run checklist on an empty instance
- Node figures from the agent's new /stats (BIND's statistics channel on 127.0.0.1:8053, added to top.conf; Kea's lease counts), kept per minute for two days and as 15-minute averages for 30 days
- A health dot on the top bar, and GET /api/v1/status for monitoring
- Secondary zones show their loaded serial on the Zones list (they showed "not loaded")
- DHCP subnets have Overview, Addresses and Settings tabs; leases and reservations are one table, and Reserve turns a lease into a reservation; Kea's in-pool reservations no longer warn
- A Jobs page (/jobs) with filters, readable job names, and an audit log with labels that hides sign-ins unless asked
- Relative times ("5 min ago") for status times, with the full time on hover
- Kea keeps trying an interface that isn't up yet when it starts (at boot) instead of listening on nothing, and a Kea that isn't running or listening is flagged on the Dashboard and the node's DHCP card
- A node that doesn't answer shows no old values on the Dashboard, and the DHCP and Time tiles leave it out
- A consistency pass: one form ending (Cancel before the main button), "Add …" everywhere, a two-column node page, the SOA as one line, phone tables that keep IPs whole, a folding help menu on phones, and a dark API docs page with the app's top bar


## 3.2.0 — 2026-10-31

- Time sync on the nodes: Set up time sync installs chrony (replacing systemd-timesyncd), with one list of sources for every node on Settings → Time, reviewed (chronyd -p) and applied node by node with rollback
- Nodes can serve time to the networks you name, and keep serving when their sources are unreachable (orphan); the DHCP subnet form suggests them as NTP servers
- Each node shows chrony's source, stratum and offset; nodes with no usable time source, chrony down or a hand-edited config are flagged
- Re-adopt and the API include time (GET /api/v1/ntp)


## 3.1.0 — 2026-10-31

- A REST API under /api/v1 with a Swagger page (/api/docs): nodes, zones, records, drafts, publishes, history, jobs, and DHCP subnets, leases and reservations
- API tokens per user, read-only or full, made on the Users tab or My account (or `liteblox token`), shown once and stored hashed
- Records are addressed by content, and If-Match guards against changes made meanwhile (a dynamic zone's per-record token ignores DHCP traffic elsewhere)
- Edits from the pages and the API to one zone are serialized, and two DHCP changes can't run at once
- Help: "The API"


## 3.0.0 — 2026-10-31

- DHCP with Kea on the BIND nodes: the interfaces each serves, subnets, pools and options, lease times, reservations and a live leases view, with each change previewed, checked by Kea and rolled back if it fails
- DHCP clients registered in DNS (DDNS into dynamic zones, following the primary on a promote)
- A DHCP failover pair (hot-standby, mutual TLS on a link you choose)
- Re-adopt: a new LiteBlox rebuilds its data from the nodes after its own is lost
- Node clock checks, a Danger zone on the node page, and a DHCP card on the Dashboard


## 2.1.0 — 2026-10-28

- Wider pages: record grids, nodes, history, backups, jobs and help use the screen's width; forms and running text stay narrow
- Busy dynamic zones: a grid edit is checked only against the record set it changes, so DHCP leases landing meanwhile no longer refuse it
- Taking over a server imports its dynamic zones whose update rules are TSIG key grants (held with rndc freeze for the switch)
- PTR updates that fail after a publish are listed on the forward zone's page, with Retry and Drop
- Switching a zone off dynamic (or demoting its primary) removes named's old file and journal from dyn/ (re-run Repair / upgrade agent on each node)
- Fixed: on a node whose zone files were in /var/lib/bind, named couldn't write journals or transferred copies in LiteBlox's dirs there
- A node still catching up after a promote or reconcile ends the job with a warning, not a failure


## 2.0.0 — 2026-10-28

- LiteBlox takes over each node's whole BIND config (fresh servers, or existing ones after an equivalence-checked preview); the node's own files move to /etc/bind/pre-liteblox/
- One primary with secondaries (NOTIFY + IXFR signed with LiteBlox's key) replaces dual-master; Promote moves the primary, also with the old one down
- A health check every minute: a returning old primary is demoted automatically, with a report of records only it had
- Config drift: hand edits to the generated files are flagged, with Overwrite, Keep (server settings) and a chooser for a hand-made second primary
- Zone kinds: forward, reverse and forwarding only (with validate-except)
- Per-node server settings (recursion, forwarders, DNSSEC, allow-query, listen-on, extras) and global ACLs, applied node by node with probes and rollback
- Dynamic zones: RFC 2136 updates, grid edits sent as guarded updates, history snapshots; TSIG client keys with per-zone grants
- Docs rewritten for v2, docker first; upgrading from 1.x: repair agents, take over each node, make one the primary


## 1.0.1 — 2026-10-27

- Key secrets are masked in a node's printed config (re-run Repair / upgrade agent on each node; LiteBlox masks them either way)
- Docs: userns_mode keep-id in the compose file is podman-only; Docker notes in the README and install guide


## 1.0.0 — 2026-10-27

- DNS for dual-master BIND: node setup and repair over SSH, an mTLS agent on each node, zone import and adoption
- Row-based zone editor with drafts, review, two-phase publish and drift detection
- Managed zones, reverse zones from a network, automatic PTR records
- Zone files kept in canonical record order; Nameservers card with NS/node checks
- History with commit messages, compare and restore; scheduled node config backups
- Users page, My account and audit log; built-in help


## 0.1.0 — 2026-10-24

- Project scaffold: FastAPI app, local accounts with admin/readonly roles, SQLite, CLI
- Container image, compose file, and the podman release pipeline in deploy/
