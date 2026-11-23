# The API

LiteBlox has a JSON API under `/api/v1`. Scripts, monitoring and other tools use it to read nodes, zones, records and DHCP leases, and to change records and DHCP reservations. Every endpoint is listed, with its fields, on the **API page** (`/api/docs`), which any logged-in user can open. Calls go through the same checks as the pages, so a publish is still reviewed against named-checkzone and the nodes, and a DHCP change still goes to the standby first and rolls back if Kea refuses it.

## Tokens

Every call needs an **API token**, sent as a header:

```text
Authorization: Bearer lbx_…
```

- **Where:** your own tokens are on **My account → API tokens**. Admins make and revoke anyone's on the **Users** tab, which also suits a service account (a `readonly` user called `monitoring`, say). From the command line: `liteblox token add USER NAME [--read-only] [--expires DAYS]`.
- **Scope:**
    - **read only**: GET calls only.
    - **full**: whatever the token's user may do. An admin's full token can change things; a readonly user's full token still only reads.
- The token is **shown once**, when it's made. LiteBlox keeps only a hash of it: if it's lost, revoke it and make another.
- The user's role is checked on **every call**, so a role change or a deleted user applies at once. **Changing a password doesn't revoke tokens**: revoke them on the same page.
- An optional expiry (in days); the token list shows when each one was last used, and from where.
- The API takes only tokens. A browser's login session isn't accepted on `/api/v1`, and a token doesn't log anyone into the pages.

## Trying it

On the API page, **Authorize** with a token, then **Try it out** on any endpoint. From a shell (`$LB` is LiteBlox's address, `$TOKEN` the token):

```bash
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/me
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/zones
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/zones/example.com/records
```

## Records

A record's `id` comes from its content (owner, type and data), so it stays the same while the record does, whatever else changes in the zone. Changing a record gives it a new id, which the answer includes.

**A static zone** changes in its **draft**, as in the grid. Look at the draft, then publish it:

```bash
# add a record (and its PTR, when the zone's auto-PTR is on)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/zones/example.com/records \
     -d '{"name": "web", "type": "A", "data": "192.168.0.20"}'

# what publishing would change: added/removed/changed records, the diff, named-checkzone, linked PTR drafts
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/zones/example.com/draft

# publish it (with the PTR drafts linked to it); the answer is a job to poll
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/zones/example.com/publish -d '{"message": "Add web"}'
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/jobs/42
```

- `data` is the record data as a zone file writes it: `10 mail.example.com.` for an MX, TXT as `"quoted strings"`. `ttl` is seconds or `1h`/`30m`; leave it out for the zone's default.
- `PATCH /zones/{zone}/records/{id}` changes only the fields you send. `DELETE` takes `?ptr=false` to leave the PTR alone.
- `PUT /zones/{zone}/soa` changes the SOA's names and timers. The serial stays LiteBlox's.
- `DELETE /zones/{zone}/draft` discards the draft, with its linked PTR drafts.
- `PUT /zones/{zone}/notes` with `{"notes": "…"}` replaces the zone's [notes](/help/editing#zone-notes); `GET /zones/{zone}` returns them. They're kept in LiteBlox only, so this works for any zone and nothing is published.
- `GET /zones/{zone}/text` returns the zone file. `GET /zones/{zone}/history` lists its versions, and `GET /zones/{zone}/history/{sha}` returns one version's text.

**A dynamic zone** changes at once, as one guarded update to its primary, as a grid edit does. It has no draft and nothing to publish.

### Many changes at once

`POST /zones/{zone}/records/batch` takes a list of ops and makes them as **one change**: all of them, or none.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/zones/example.com/records/batch -d '{
  "ops": [
    {"op": "add", "name": "web1", "type": "A", "data": "192.168.0.21", "comment": "rack 2"},
    {"op": "add", "name": "web2", "type": "A", "data": "192.168.0.22", "ttl": "10m"},
    {"op": "change", "id": "<an id from GET …/records>", "ttl": 600},
    {"op": "delete", "id": "<another id>"}
  ]}'
```

- `add` needs `name`, `type` and `data`; `ttl` and `comment` are optional. `change` takes an `id` and only the fields to change, as `PATCH` does. `delete` takes an `id`. Ids are the records' ids before the batch, and each record can appear in one op only. Up to 2000 ops.
- Each op is checked against the zone as the ops before it leave it, the way [Add many](/help/editing#adding-many-records) checks its lines. If any op isn't valid, nothing changes, and the **422** lists every bad op: `{"detail": …, "errors": [{"index": 1, "errors": {"value": …}}]}`.
- The answer has `records`, one per op in order: the record each op became, with its new id (`null` for a delete). It also has the zone's new `rev`, and any notes and warnings.
- A static zone gets them all in its draft. Publish it as usual. PTRs follow A records unless `"ptr": false`, and the reverse zones' drafts are linked so they publish together.
- A dynamic zone gets **one** update. If a record's set changed on the server meanwhile, the update is refused whole (409).
- `If-Match` takes the zone's `rev`. In a dynamic zone it can instead list the `rr` of every record the batch changes or deletes.

## Changes made meanwhile

- `GET …/records` returns the zone's `rev` (also as the `ETag` header). Send it back as `If-Match` on a write, and LiteBlox refuses the write with **412** if the zone changed since. In a static zone, publishing with `If-Match` refuses a draft that changed after you looked at it.
- In a dynamic zone, DHCP changes the zone all the time, so each record also has an `rr` token. As `If-Match`, it checks only that record's set (its name and type), so leases landing elsewhere don't get in the way:

        curl -s -H "Authorization: Bearer $TOKEN" -H "If-Match: \"$RR\"" -H 'Content-Type: application/json' \
             -X PATCH $LB/api/v1/zones/ddns.lab/records/$ID -d '{"data": "192.168.0.31"}'

- Without `If-Match`, a write still never hits the wrong record, since ids are by content. Two writes to one zone don't interleave, whether from the pages or the API.

## Jobs

Publishing and DHCP changes run as **jobs**, as they do from the pages. The call answers **202** with `{"job": N}` (and a `Location` header). Poll `GET /api/v1/jobs/N` until `status` is `ok` or `failed`; its `log` is what the job page shows. `GET /api/v1/jobs` lists recent ones.

## DHCP

```bash
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/dhcp            # servers, the failover pair, settings
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/dhcp/subnets    # with their reservations
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/dhcp/leases     # live from Kea (?subnet=ID)

# reserve an address (a job: every DHCP node, the standby first)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/dhcp/subnets/2/reservations \
     -d '{"hw_address": "aa:bb:cc:dd:ee:ff", "ip_address": "192.168.0.60", "hostname": "printer"}'

# delete a lease now (its DNS names go too; the client asks again at its next renewal)
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE $LB/api/v1/dhcp/leases/192.168.0.123
```

- A reservation without `ip_address` (or with `""`) is [name-only](/help/dhcp#name-only-reservations), in a subnet that registers clients and with a `hostname`.
- A reservation's answer lists `warnings`, for example another client holding the address right now. `PATCH` changes only the fields you send; `DELETE` removes it. A failover pair's leases are read from its primary, or from the standby when the primary doesn't answer.
- The settings in `GET /dhcp` include where clients are registered in DNS: `ddns_mode` (`liteblox`, `external` or `off`), and for `external` the `ddns_server` and `ddns_port` (never the key's secret). A subnet's `ddns` (`zone`, `suffix`) is where its clients go under that mode (`null` when it registers nothing).
- Only one DHCP change runs at a time: another one gets **409** until the running job has finished.

## Search

`GET /api/v1/search?q=…` is the [Search](/help/search) page as JSON: `records`, `reservations`, `leases`, `zones`, `subnets` and `devices`, each with its `count` and up to `limit` (default 200) `items`. A query for one IPv4 address also gets `address`: its names, PTR, reservation, lease, subnet, and the `checks` that didn't add up. A dynamic zone searched from its history because its primary didn't answer gives its records `as_of`; what a short query didn't read live is in `skipped`. A read-only token is enough.

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$LB/api/v1/search?q=192.168.0.50" | jq .address
```

## IPAM

Everything on the [IPAM](/help/ipam) pages, under `/api/v1/ipam`: networks (`GET`, `POST`, `PATCH`, `DELETE`) and their ranges, a network's `addresses` (one /24 per `page`, `used_only` to leave the free ones out), what the nodes `seen` (and `DELETE /ipam/seen/{ip}` to forget it), `flapping` addresses and their `ack`, and `devices` (`PUT` a label and comment, and `repeater` to mark a Wi-Fi repeater's MAC).

**Next free** finds addresses nothing uses and holds them for a few minutes, then **assign** puts names on them:

```bash
# the next 3 free addresses in a row, held for 10 minutes
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/ipam/next-free -d '{"network": "192.168.10.0/24", "count": 3}'
# A records (and PTRs) for them, published; a group to remove them by later
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST $LB/api/v1/ipam/assign \
     -d '{"ips": ["192.168.10.81", "192.168.10.82", "192.168.10.83"], "name": "k8s-{n}", "zone": "lab.example.com", "group": "k8s"}'
# and gone again: only what assign made
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -X POST $LB/api/v1/ipam/unassign -d '{"group": "k8s"}'
```

- `next-free` takes one of `network` (an IPAM network's id or prefix), `range` (a range's id) or `subnet` (a DHCP subnet: outside its pools, for a reservation), and `count` (1 to 64), `align`, `hold`, `minutes`. Its answer says whether the addresses were `checked` on the network, and gives the `hold_id`. `DELETE /ipam/holds/{ip}` or `DELETE /ipam/holds?hold_id=` releases them early.
- `assign` with a `mac` (or `macs`, one per address) makes DHCP reservations, with the name as their hostname; without, A records in `zone` (or the zone the full name is in), then a publish unless `publish` is false. With `"target": "ipam"` (the default when the DNS module is off) it makes [IPAM records](/help/ipam#ipam-records) instead of A records: nothing goes to DNS, and a MAC outside the DHCP subnets stays on the record. Its answer lists the `jobs`, and what each address got in `kinds` (`static`, `reservation`, `ipam`).
- `names` are the IPAM records: `GET /ipam/names` (`network` to narrow it), `GET`, `PUT` (`name`, `mac`, `comment`) and `DELETE /ipam/names/{ip}`. A network's `addresses` give each one's `ipam_name`, and its `rdns` when a resolver is set ([PTR lookups](/help/ipam#ptr-lookups-rdns)).
- `unassign` takes `ips`, a `range` (`"192.168.10.81-192.168.10.83"`) or a `group`, and removes only what `assign` made: anything else at those addresses is listed in `skipped`.

These need a full token; the reads work with a read-only one.

## The command line (lbcli)

[lbcli.py](/static/lbcli.py) does the same from a shell: one file, Python 3.9 or later, nothing to install. It reads the server from `LITEBLOX_URL` (or `--url`) and the token from `LITEBLOX_TOKEN` (or `--token-file`).

```bash
export LITEBLOX_URL=https://liteblox.example.com LITEBLOX_TOKEN=lbx_…
lbcli.py next --subnet 192.168.1.0/24 --blocksize 3        # 192.168.1.81, 192.168.1.82, 192.168.1.83
lbcli.py reserve 'k8s-{n}' --network 192.168.10.0/24 --blocksize 3 --zone lab.example.com --group k8s
lbcli.py reserve printer --subnet 192.168.1.0/24 --mac aa:bb:cc:dd:ee:ff   # a DHCP reservation
lbcli.py reserve nas --network 192.168.1.0/24 --ipam                        # a name kept in IPAM only
lbcli.py unassign --group k8s
lbcli.py release --hold 3f9c0a1b2c4d
lbcli.py show 192.168.1.20
```

With LiteBlox's own [HTTPS](/help/https) and a self-signed certificate, give the certificate (**Settings → HTTPS → Download the certificate**) with `--ca FILE` or `LITEBLOX_CA`, rather than turning the check off with `--insecure`.

`reserve` takes the next free addresses (or `--ip`) and assigns them in one go; `--json` prints the API's answer for scripts. Errors start with `ERROR:` and exit 1.

## Agent upgrades

Each node in `GET /api/v1/nodes` says `can_upgrade` when its agent is older than this LiteBlox's and can be upgraded over mutual TLS (see [Upgrading an agent](/help/install#upgrading-an-agent)). `POST /api/v1/nodes/{name}/upgrade-agent` does it, as the node page's **Upgrade agent** button does, and answers 202 with a job; 409 means it can't (already current, unreachable, or it needs Repair / upgrade agent over SSH first). It needs an admin's full token.

## Time

`GET /api/v1/ntp` returns the sources every node uses and, for each node with time sync, whether it serves time, to which networks, and chrony's last state (synced, the source it follows, stratum, offset). Each node in `GET /api/v1/nodes` carries the same state as `time`.

## Status

`GET /api/v1/status` is the Dashboard as JSON, for a monitoring system: `level` (`ok`, `warn` or `error`), `attention` (how many problems need an admin), `checked_at` (when the health check last heard from a node, UTC), the `problems` (each with `severity`, `area`, `what`, the page that fixes it as `link`, and the `node`), and the `tiles`. A read-only token is enough.

```bash
curl -s -H "Authorization: Bearer $TOKEN" $LB/api/v1/status | jq -r .level
```

## Errors

| Status | Meaning |
|---|---|
| 401 | no token, or it's unknown, revoked or expired |
| 403 | the token is read-only, or its user isn't an admin |
| 404 | no such zone, record, subnet, reservation, lease, network or job |
| 409 | not possible as things are: nothing free (left) for next free, an address already assigned, a forwarding zone has no records, a dynamic zone has no draft, a publish or DHCP change is already running, or a dynamic zone changed on its primary during the update |
| 412 | `If-Match` didn't match: read it again |
| 422 | not valid. `errors` says which field and why (`{"detail": …, "errors": {"value": …}}`) |
| 502 | a node or a zone's primary didn't answer |

Every other answer is JSON, with `detail` saying what went wrong.

## What it doesn't do (yet)

These are on the pages:
- creating and deleting zones, and zone settings
- nodes (setup, take over, Repair, server settings, promote), except upgrading an agent
- TSIG keys and ACLs
- DHCP subnets, settings, interfaces and the failover pair

Every write through the API is in the audit log under the token's user, with the token's name.
