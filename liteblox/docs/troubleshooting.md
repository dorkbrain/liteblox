# Troubleshooting

## Where to look

- **The job page**: setup, takeover, publish, zone and settings changes, promote and the health check's demotions each have a log at `/jobs/<n>`, linked from the node's page (Recent jobs) and the zone's History tab (Publishes).
- **The Jobs page** (`/jobs`, linked from **Nodes**, the Dashboard's Recent activity and every job's page) lists recent jobs on every node, newest first, with how long each took. Filter by kind, status (running, ok, failed) or node; **Older** goes further back. A job that ended **ok** with ⚠ lines in its log is marked *warnings*. Jobs the health check starts show `liteblox` as their user, command-line ones `cli`.
- **LiteBlox's own log**: `docker compose logs liteblox` (scheduled backups, errors).
- **On a node**:

        systemctl status liteblox-agent
        journalctl -u liteblox-agent -n 50
        journalctl -u named -n 50
        sudo named-checkconf -px          # the configuration named runs, key secrets masked
        journalctl -u kea-dhcp4-server -u kea-dhcp-ddns-server -n 50    # on a DHCP node

## A node shows "error" or "cannot reach agent"

- Is the agent running? `systemctl status liteblox-agent` on the node. **Repair / upgrade agent** reinstalls and restarts it.
- Can the LiteBlox host reach TCP 8530 on the node? Check the node's firewall. From the LiteBlox host: `nc -vz NODE 8530`.
- Is the node's clock right? Certificates are refused if it's far off (`timedatectl`).
- Did the node's address change? See [A node moved to a new address](#a-node-moved-to-a-new-address).

The health check asks every node once a minute, so the status corrects itself within a minute of the node coming back.

## Setup fails

| Message | Meaning |
|---|---|
| `SSH login to … failed` | wrong user or password, or password login is disabled in sshd. Try the CLI with keys: `liteblox node bootstrap NODE --ssh-user USER --use-ssh-keys` |
| `host key for … does NOT match the pinned key` | see [The SSH host key changed](#the-ssh-host-key-changed) |
| `sudo failed: … check the sudo password` | the account isn't in group `sudo`, or the sudo password differs from the SSH one: fill in **sudo password** |
| `BIND is not installed` | tick **Install BIND if it's missing**, or `apt install bind9 bind9-utils bind9-dnsutils` |
| `named-checkconf` failed | the node's own configuration has an error; fix it before setup |
| `liteblox-agent did not start` | the log includes the agent's journal; usually a Python or permissions problem |
| `agent did not answer over mTLS` | the agent started but LiteBlox can't reach TCP 8530 (firewall) |
| `Not taking over: …` | the server has a configuration of its own. Setup finished; review the takeover on the node's page ([Bringing in existing servers](/help/existing-servers)) |

## Take over is blocked

The preview lists what stops it, and nothing changes on the node:

- **"the generated config is not equivalent to the node's"** with a diff: LiteBlox's version would behave differently. Usually a statement in an unusual form; the diff shows which. Change it on the server (or remove it), then open the preview again.
- **views**, secondary or stub zones, dynamic zones LiteBlox can't import, options with paths: see [What blocks a takeover](/help/existing-servers#what-blocks-a-takeover).
- **an ACL, key or zone LiteBlox already has with other contents**: make the two agree (on the server, or in LiteBlox) first.
- **"the node's config changed since the preview"**: open the preview again.

- **"LiteBlox already manages the whole BIND config on this node"** on a node this LiteBlox doesn't manage: another LiteBlox generated it, usually one whose data was lost. Re-adopt it instead ([Disaster recovery](/help/backups#disaster-recovery)).

If the takeover itself fails (*did not serve as before after the takeover*: a zone doesn't answer with the same serial), the node is rolled back to its own files and the job log says why.

## Re-adopt is refused

Re-adopting rebuilds LiteBlox's data from nodes another LiteBlox managed, and changes nothing on them. So it refuses rather than guess:

- **a diff under a node:** rendering that node's config back from the rebuilt data doesn't give its files. Someone changed a generated file by hand, or an older LiteBlox version wrote it. Put the file back as it was (a node backup has it), or untick the node. There's no Overwrite here: the old LiteBlox's data is what's being recovered.
- **"is not one of the nodes being re-adopted":** add the missing node (the primary, a secondary, or the other half of the failover pair) under its old name, repair it, and preview again.
- **"Re-adopting only rebuilds into an empty LiteBlox":** this LiteBlox already has zones, keys or managed nodes. Re-adopt into a fresh install.

## A zone shows "not writable"

The agent can't write that zone file or its directory. Re-run setup with **Make /etc/bind and the zone files group-writable** ticked, or give group `bind` write access yourself.

## Publish is blocked or fails

| Where | Meaning and fix |
|---|---|
| Review: **changed on the node** | someone edited the file on the primary by hand; choose **Keep the node's edit** or **Overwrite it on the next publish** |
| Review: **unreachable** | see [cannot reach agent](#a-node-shows-error-or-cannot-reach-agent) |
| *take over first* | a node serving the zone isn't taken over yet; take it over from its page |
| *a role change (promote, demote) is running* | wait for that job to finish, then publish |
| *the published copy changed after this draft was started* | another import, restore or publish happened meanwhile; discard the draft and redo the change |
| *changed since you reviewed it* | someone edited the draft after you opened Review; reload Review |
| `named-checkzone rejected` | the zone has an error; the log shows the line |
| *staging failed on …* | the primary's own `named-checkzone` refused the file, or it couldn't write it; the log has the details |
| **partial**: *hasn't transferred serial N yet* | see [A secondary is behind](#a-secondary-is-behind) |
| **partial**: *not every node is serving it* | the primary failed to reload (it kept its previous file) or answers with an old serial; fix the node, then **Republish to all nodes** |

If the serial check fails although the node reloaded, the node may answer DNS on a different address than LiteBlox asks. Set its **DNS address** on the node's page.

## A secondary is behind

A secondary transfers each zone from the primary after the primary notifies it. If it doesn't catch up:

- Can it reach the primary on TCP 53, and is the primary's address right? The primary is listed by its **DNS address** (on its page) in the secondary's `primaries`.
- `journalctl -u named` on the secondary shows the transfer attempts; on the primary, the transfers it served.
- Does the primary's **Answer queries from** (its Server settings, or the zone's) leave the secondary out? LiteBlox lets its own key through a restricted list, but check the log.
- `sudo rndc refresh ZONE` on the secondary makes it check right away.

## Dynamic zones

| Message | Meaning |
|---|---|
| *That record changed on the server since you loaded the page … nothing was written* | DHCP, ACME, another tab or person changed the record set you were editing after you loaded the page. Reload and redo the edit. |
| *This zone changed on the server since you loaded it … nothing was written* | the same, caught by the update's own guard (it changed between LiteBlox reading the zone and sending your edit), or from a page loaded before 2.1. Reload and redo it. |
| **PTR updates that didn't go out** on a zone's page | its PTR changes for a dynamic reverse zone failed after a publish: **Retry** once the reverse zone's primary takes updates again ([details](/help/dynamic#ptr-updates-that-didnt-go-out)) |
| *can't read ZONE from its primary* | LiteBlox couldn't transfer the zone from the primary: is it up, and does TCP 53 reach it? |
| *refused the update* | named refused it: the key isn't granted for that name and type, or the zone isn't dynamic on that node. Check the grants on **Settings → TSIG keys**. |
| a client's update is `REFUSED` | the client's key isn't granted that name or type in this zone, it signs with another key, or it sends to a secondary instead of the primary |

## DHCP (Kea)

| What you see | Meaning and fix |
|---|---|
| setup stops at *Kea did not start* | the log shows Kea's last journal lines. `sudo journalctl -u kea-dhcp4-server` on the node has the rest. |
| **kea-dhcp4** or **DDNS (D2)** *not answering* | the service is stopped, or its socket proxy is: on the node, `systemctl status kea-dhcp4-server liteblox-kea4-ctrl.socket`. A *Permission denied* means the agent isn't in the `_kea` group yet: run **Repair / upgrade agent**. |
| *Kea is not set up on this node* | run **Set up DHCP** on the node's page first |
| clients get no address | Check, in order: is the interface ticked under **DHCP → Servers**? Is the subnet on that interface's network (its page says which interface)? Is the pool full? Does a firewall on the node drop UDP 67/68? Another DHCP server on the network may also answer first. |
| a reserved client still has its old address | it keeps its lease until it renews (half the lease time). **Delete lease** on the subnet's **Addresses** tab moves it now. Also check the MAC: a phone or laptop may use a random ("private") MAC per network, which changes. |
| *no interface Kea serves has an address in …* | the serving node has no address in that subnet on a ticked interface: tick the interface first, or check the subnet |
| *Kea stopped working after the change* | Kea reloaded, but a service stopped answering or couldn't open its sockets (e.g. the interface is down). The change was rolled back; `journalctl -u kea-dhcp4-server` on the node says why. |
| *Kea rejected kea-dhcp4.conf* | `kea-dhcp4 -t` refused the new configuration, so nothing changed. The job log has Kea's message. |
| *Kea did not take the new config; rolled back* | Kea refused it at reload. The agent put the previous files back and reloaded them. |
| clients get an address but no DNS name | the subnet's **Register clients** is off, the client sends no hostname, or the name is already taken by a record DHCP didn't register (DHCP never overwrites those). `journalctl -u kea-dhcp-ddns-server` on the DHCP node says which; a `REFUSED` there means the key lacks a grant (the subnet's review lists what's missing). `BADTIME` means a clock is off: see [A node's clock is off](#a-nodes-clock-is-off). |
| **not listening** on the Dashboard, *Kea isn't serving DHCP* or *can't listen for DHCP yet* | kea-dhcp4 runs but couldn't open a ticked interface, usually because it started before the interface was up (at boot). It tries again every 5 seconds for 10 minutes (*retrying*), and a failover partner keeps standing by meanwhile, so nobody answers. Once those retries run out (*failed*), the health check reloads Kea within a minute of the interface coming up (at most every 10 minutes). If Kea's config was changed on the node, LiteBlox leaves it alone: **Rewrite DHCP config** on the node's page (which undoes that change) makes Kea try again. *not running* means kea-dhcp4 itself doesn't answer: see the **kea-dhcp4** row above. |
| **DHCP partner-down** on a node | its failover partner stopped answering, so this node serves alone. It goes back to normal by itself when the partner returns. If the partner is up, check TCP 8001 between the link addresses and `journalctl -u kea-dhcp4-server` on both (look for `HA_`). |
| **DHCP terminated** | Kea stopped failover, almost always because the two clocks are over 60 seconds apart. Fix the clocks ([A node's clock is off](#a-nodes-clock-is-off)), then **Rewrite DHCP config** on both nodes' pages. |
| **DHCP waiting** or **syncing** for long | the two can't complete their handshake: TLS (a node's certificate is checked against LiteBlox's CA), the link address or the port. The job that paired them says why if it rolled back. |
| *DHCP config is behind* on the Dashboard | the node missed a DHCP change while it was unreachable (a promote moving where names are registered, say). The health check writes it again by itself, at most every 10 minutes; **Rewrite DHCP config** on its page does it now. |
| **changed outside LiteBlox** on the DHCP card | someone edited `/etc/kea/*.conf` on the node: see the changes on the card, then **Overwrite the changes** |

## A node is flagged

| Flag | Meaning and fix |
|---|---|
| **demote pending** / **update pending** | it was down when another node was promoted. It's brought in line automatically within a minute of answering again ([The health check](/help/failover#the-health-check)); if that fails, the job is on its page and it's tried again after 10 minutes. |
| **config changed** | its generated BIND files were edited outside LiteBlox: [Config drift](/help/failover#config-drift) |
| **second primary** | it declares zones as primary by hand: [A second primary](/help/failover#a-second-primary) |
| **report** | records only its copies had were kept when it was brought in line: [Demote reports](/help/failover#demote-reports) |
| **upgrade** | it runs another agent build than this LiteBlox ships: **Repair / upgrade agent** |

## Backups are "stale"

No successful backup in 48 hours. Open the node's **Backups** page: failed attempts are listed with their error, usually the agent being unreachable. **Back up now** retries.

## The SSH host key changed

LiteBlox pins each node's SSH host key and refuses to connect when it changes, which protects the setup password. It changes legitimately when a server is reinstalled or replaced, or its SSH keys are regenerated. To pin the new key:

1. On the server, note its fingerprint: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. On the node's page, choose **Change address or host key**, leave the address as it is, and **Read host key**.
3. LiteBlox shows the key it received next to the pinned one. Confirm only if it matches what the server showed.

From the command line: `liteblox node edit NAME`.

The agent itself doesn't use SSH, so a node that's already set up keeps working until it needs repair or upgrade. A reinstalled server needs **Repair / upgrade agent** anyway, since the agent is gone with the old system; then take it over again.

## A node moved to a new address

The agent's certificate names the address LiteBlox reaches it by, and its config names its port. After changing either on the server:

1. On the node's page, choose **Change address or host key**, enter the new address (and ports), and confirm the host key as above.
2. The node's page then says the certificate no longer matches. Run **Repair / upgrade agent**, which issues a certificate for the new address.
3. If the node is the primary or a secondary, run **Make … the primary** again on the Nodes page (with the current primary), so the others use the new address for transfers and NOTIFY.

From the command line: `liteblox node edit NAME --host NEW-ADDRESS`, then `liteblox node bootstrap NAME --ssh-user USER`.

LiteBlox doesn't touch DNS data for you: update the node's own A/AAAA and NS records, and any **Also notify** or **Allow transfers to** lists that name the old address.

## Removing a node

**Remove from LiteBlox**, in the **Danger zone** at the bottom of the node's page (or `liteblox node remove NAME`), makes LiteBlox forget it: its zones, publish results and backup list. It doesn't contact the server, so it works for a dead one too. Its backup files stay in `./backups/NAME/`.

- A zone that no other node serves stays in LiteBlox, with its history, but can't be published until a node serves it again.
- If it was the primary, [promote](/help/failover#promote-moving-the-primary) another node first.
- If you're replacing a dead server under the same name, **don't remove it**: [re-pin the host key](#the-ssh-host-key-changed) and run **Repair / upgrade agent** instead, so its backups stay listed.

Nothing on the server changes: BIND keeps serving what it has. To stop it serving LiteBlox's zones, use **Stop serving on a node** in each zone's **Settings → Danger zone** *before* removing the node, while it's reachable. To hand the server back to its own configuration afterwards:

```bash
ls /etc/bind/pre-liteblox/                              # the takeover's folder, e.g. 20261028T182537Z
sudo cp -a /etc/bind/pre-liteblox/STAMP/. /etc/bind/
sudo rm -rf /etc/bind/liteblox
sudo named-checkconf && sudo systemctl restart named
```

and to uninstall the agent:

```bash
sudo systemctl disable --now liteblox-agent
sudo rm -rf /usr/local/lib/liteblox-agent /etc/liteblox-agent /var/lib/liteblox-agent \
    /etc/systemd/system/liteblox-agent.service
sudo systemctl daemon-reload
sudo userdel liteblox-agent
```

## A node's clock is off

The health check compares each node's clock with LiteBlox's every minute. The Nodes page and the node's page show:

| Flag | Meaning |
|---|---|
| **clock +45s** (yellow) | 30 seconds or more apart. DHCP failover pairs give up at 60 seconds. |
| **clock +200s** (red) | 120 seconds or more apart. Signed zone transfers and DNS updates (DHCP's, ACME's, LiteBlox's own) fail at 300 seconds with `BADTIME`. |
| **clock not synced** | the node's clock isn't kept by NTP, so it will drift |

On the node, `timedatectl` shows the state. `sudo timedatectl set-ntp true` turns NTP on (Debian: `apt install systemd-timesyncd` first), or let LiteBlox run chrony there ([Time (NTP)](/help/ntp)). The flag clears at the next check after the clock is right. The LiteBlox container takes its time from its host, so check the host too if every node shows the same offset.

## Time sync (chrony)

| What you see | Meaning and fix |
|---|---|
| **time: no source** | chrony runs but can't use any source: none answers, or they disagree. On the node, `chronyc sources` lists them (`^?` = not reachable). Check that UDP 123 to them isn't blocked, and that a pool's name resolves. |
| **time: chrony down** | chrony isn't running. `systemctl status chrony` and `journalctl -u chrony` on the node say why. **Rewrite time config** writes LiteBlox's file again, which restarts it. |
| *chronyd rejected chrony.conf* at review or apply | chrony's own check (`chronyd -p`) refused the new file, so nothing changed. The message names the line. |
| *chrony is not running after the change* | chrony didn't come back on the new file; the agent put the previous one back. |
| *chrony was not restarted* | the path unit that restarts chrony is missing or off: run **Set up time sync** on the node again. |
| **time config changed** | `chrony.conf` was edited on the node: see the card, then **Overwrite the changes** |

## Behind a proxy, LiteBlox still says http

Add node warns about plain text, `/api/docs` and the token page show `http://` URLs, or the audit log shows one address for everyone: LiteBlox doesn't trust the proxy's `X-Forwarded-*` headers. Set `FORWARDED_ALLOW_IPS` to the address the proxy's requests come from. For a proxy in a container on the same docker host, that's the docker network's gateway, not the host's address ([details](/help/install#https)). Then `docker compose up -d --force-recreate`.

## Locked out of LiteBlox

```bash
docker compose exec liteblox liteblox user passwd admin
docker compose exec liteblox liteblox user add rescue --role admin
```

## HTTPS doesn't work, or plain HTTP says it isn't supported

- **"HTTP isn't supported here"** on port 53530: [HTTPS only](/help/https#https-only) is on. Open `https://HOST:53443`, or allow plain HTTP again from the docker host: `docker compose exec liteblox liteblox https allow-http`.
- **Port 53443 doesn't answer:** check that `docker-compose.yaml` publishes it (`- "53443:53443"`) and the container was recreated since (`docker compose up -d`). `docker compose exec liteblox liteblox https status` says whether LiteBlox is listening, and why not.
- **The browser refuses the certificate:** a self-signed one has to be trusted first, or its warning accepted ([Trusting a self-signed certificate](/help/https#trusting-a-self-signed-certificate)). Its names must include the name or address in the address bar: make a new one with the right names on **Settings → HTTPS**, or `liteblox https regenerate --name NAME`.
- **A renewed certificate isn't picked up:** the tab and the Dashboard say why (a key that doesn't match, a file uid 1000 can't read). LiteBlox keeps serving the previous certificate meanwhile and tries again every 5 seconds ([The files, and live updates](/help/https#the-files-and-live-updates)).
