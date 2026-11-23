"""SQLite connection handling and schema migrations (tracked in PRAGMA user_version)."""

import sqlite3

from fastapi import Request

# Append-only: each entry upgrades the schema by one version. Never edit a
# migration that has shipped; add a new one instead.
MIGRATIONS = [
    # 1: local accounts and the audit trail
    """
    CREATE TABLE users (
        id            INTEGER PRIMARY KEY,
        username      TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL CHECK (role IN ('admin', 'readonly')),
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        last_login_at TEXT
    );
    CREATE TABLE audit (
        id       INTEGER PRIMARY KEY,
        at       TEXT NOT NULL DEFAULT (datetime('now')),
        username TEXT,
        action   TEXT NOT NULL,
        detail   TEXT
    );
    """,
    # 2: BIND nodes, zones LiteBlox manages, which node serves which zone, background jobs
    """
    CREATE TABLE nodes (
        id               INTEGER PRIMARY KEY,
        name             TEXT NOT NULL UNIQUE,
        host             TEXT NOT NULL,
        ssh_port         INTEGER NOT NULL DEFAULT 22,
        agent_port       INTEGER NOT NULL DEFAULT 8530,
        host_key         TEXT NOT NULL,        -- pinned "type base64" from when the node was added
        host_key_fp      TEXT NOT NULL,        -- SHA256:... shown to the user at pin time
        status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'ready', 'error')),
        status_detail    TEXT,
        cert_fingerprint TEXT,
        cert_not_after   TEXT,
        agent_version    TEXT,
        agent_sha256     TEXT,
        named_version    TEXT,
        last_seen_at     TEXT,
        created_at       TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE zones (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,      -- lowercase, no trailing dot
        mode       TEXT NOT NULL DEFAULT 'local' CHECK (mode IN ('local', 'managed')),
        repo_file  TEXT NOT NULL,             -- path inside the git repo
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE zone_nodes (
        zone_id         INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        node_id         INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        node_file       TEXT NOT NULL,         -- zone file path on the node
        deployed_sha256 TEXT,                  -- hash of the file LiteBlox last read or wrote there
        PRIMARY KEY (zone_id, node_id)
    );
    CREATE TABLE jobs (
        id          INTEGER PRIMARY KEY,
        kind        TEXT NOT NULL,
        node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
        username    TEXT,
        status      TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed')),
        log         TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        finished_at TEXT
    );
    """,
    # 3: node config backups
    """
    ALTER TABLE nodes ADD COLUMN backup_keys INTEGER NOT NULL DEFAULT 1;
    CREATE TABLE backups (
        id              INTEGER PRIMARY KEY,
        node_id         INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        kind            TEXT NOT NULL CHECK (kind IN ('scheduled', 'manual', 'pre-change', 'pre-bootstrap')),
        status          TEXT NOT NULL CHECK (status IN ('ok', 'failed')),
        file            TEXT,                  -- relative to the backups dir
        size            INTEGER,
        file_count      INTEGER,
        keys_included   INTEGER,
        manifest_sha256 TEXT,                  -- the agent's hash of the file list: the dedup key
        manifest        TEXT,                  -- JSON manifest from the archive
        reason          TEXT,
        username        TEXT,
        error           TEXT,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        checked_at      TEXT                   -- last scheduled run that found nothing changed
    );
    CREATE INDEX backups_by_node ON backups (node_id, created_at);
    """,
    # 4: publishes and their per-node outcome
    """
    ALTER TABLE jobs ADD COLUMN zone_id INTEGER REFERENCES zones(id) ON DELETE SET NULL;
    CREATE TABLE deploys (
        id          INTEGER PRIMARY KEY,
        zone_id     INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        job_id      INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        username    TEXT,
        status      TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'partial', 'failed')),
        commit_sha  TEXT,
        serial      INTEGER,
        error       TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        finished_at TEXT
    );
    CREATE TABLE deploy_nodes (
        deploy_id     INTEGER NOT NULL REFERENCES deploys(id) ON DELETE CASCADE,
        node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        status        TEXT NOT NULL CHECK (status IN ('pending', 'drift', 'unreachable', 'staged', 'aborted',
                                                      'committed', 'verified', 'failed')),
        served_serial INTEGER,
        error         TEXT,
        PRIMARY KEY (deploy_id, node_id)
    );
    """,
    # 5: per-zone declaration settings for managed zones
    """
    ALTER TABLE zones ADD COLUMN notify TEXT NOT NULL DEFAULT 'no';
    ALTER TABLE zones ADD COLUMN also_notify TEXT NOT NULL DEFAULT '';
    ALTER TABLE zones ADD COLUMN allow_transfer TEXT NOT NULL DEFAULT '';
    """,
    # 6: keep PTR records in step with A/AAAA edits in this zone
    """
    ALTER TABLE zones ADD COLUMN auto_ptr INTEGER NOT NULL DEFAULT 1;
    """,
    # 7: LiteBlox writes the zone file in its own record order (dns/canonical.py)
    """
    ALTER TABLE zones ADD COLUMN sorted INTEGER NOT NULL DEFAULT 0;
    """,
    # 8: bumped on every password change; sessions from before it are logged out
    """
    ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
    """,
    # 9: the commit message the user gave a publish (NULL: the default "Publish <zone>")
    """
    ALTER TABLE deploys ADD COLUMN message TEXT;
    """,
    # 10: v2 takeover: LiteBlox generates the node's whole BIND config (bindconf/)
    """
    ALTER TABLE nodes ADD COLUMN managed INTEGER NOT NULL DEFAULT 0;   -- 1 once taken over
    ALTER TABLE nodes ADD COLUMN options TEXT;                         -- bindconf.model.NodeOptions JSON
    ALTER TABLE nodes ADD COLUMN top_extra TEXT NOT NULL DEFAULT '';
    ALTER TABLE nodes ADD COLUMN distro_includes TEXT;                 -- JSON list, kept as found
    ALTER TABLE nodes ADD COLUMN config_sha256 TEXT;                   -- render.set_sha256 of the last commit
    ALTER TABLE nodes ADD COLUMN taken_over_at TEXT;
    """,
    # 11: importing an existing config at takeover: per-zone allow-query, global ACLs and TSIG keys
    """
    ALTER TABLE zones ADD COLUMN allow_query TEXT NOT NULL DEFAULT '';
    CREATE TABLE acls (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        items      TEXT NOT NULL,              -- JSON list of address-match items
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE tsig_keys (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        algorithm  TEXT NOT NULL,
        secret     TEXT NOT NULL,
        purpose    TEXT NOT NULL DEFAULT 'imported',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    # 12: one primary node, the others its secondaries (NULL: no primary picked yet, every copy a primary)
    """
    ALTER TABLE nodes ADD COLUMN role TEXT CHECK (role IN ('primary', 'secondary'));
    ALTER TABLE nodes ADD COLUMN dns_address TEXT;     -- for primaries/also-notify and DNS checks; NULL: host
    """,
    # 13: forwarding-only zones (BIND type forward): no zone file, no records, not tied to the primary
    """
    ALTER TABLE zones ADD COLUMN kind TEXT NOT NULL DEFAULT 'primary' CHECK (kind IN ('primary', 'forwarding'));
    ALTER TABLE zones ADD COLUMN forwarders TEXT NOT NULL DEFAULT '';       -- one per line: IP [port N]
    ALTER TABLE zones ADD COLUMN forward_mode TEXT NOT NULL DEFAULT 'only'; -- only, first, '' = BIND's default (first)
    """,
    # 14: dynamic zones (RFC 2136 updates), TSIG key grants, PTR updates waiting for a forward zone's publish
    """
    ALTER TABLE zones ADD COLUMN dynamic INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE key_grants (
        id      INTEGER PRIMARY KEY,
        key_id  INTEGER NOT NULL REFERENCES tsig_keys(id) ON DELETE CASCADE,
        zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        scope   TEXT NOT NULL CHECK (scope IN ('zonesub', 'subdomain', 'name')),
        name    TEXT NOT NULL DEFAULT '',          -- for subdomain/name: an absolute name in the zone
        types   TEXT NOT NULL DEFAULT 'ANY'        -- space-separated record types
    );
    CREATE TABLE ptr_queue (
        id              INTEGER PRIMARY KEY,
        forward_zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        reverse_zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        ops             TEXT NOT NULL,             -- JSON [[kind, address, target], ...] for ptr.apply
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    # 15: promote/demote and config drift
    """
    ALTER TABLE nodes ADD COLUMN pending TEXT CHECK (pending IN ('apply', 'demote'));  -- run when it answers again
    ALTER TABLE nodes ADD COLUMN config_files TEXT;        -- JSON {role: sha256} of the last commit
    ALTER TABLE nodes ADD COLUMN drift TEXT;               -- JSON [role, ...] changed outside LiteBlox; NULL: none
    ALTER TABLE nodes ADD COLUMN second_primary TEXT;      -- JSON [zone, ...] it declares primary but shouldn't
    ALTER TABLE nodes ADD COLUMN drift_checked_at TEXT;
    CREATE TABLE demote_reports (
        id             INTEGER PRIMARY KEY,
        node_id        INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        zone_id        INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        created_at     TEXT NOT NULL DEFAULT (datetime('now')),
        node_serial    INTEGER,
        primary_serial INTEGER,
        old_text       TEXT NOT NULL,             -- the node's copy before it was demoted
        rrsets         TEXT NOT NULL,             -- JSON [[name, type, ttl, [rdata, ...]], ...] only on that copy
        resolved_at    TEXT,
        resolved_by    TEXT
    );
    """,
    # 16: PTR updates whose send failed after the forward zone's publish (shown with Retry)
    """
    ALTER TABLE ptr_queue ADD COLUMN failed_at TEXT;
    ALTER TABLE ptr_queue ADD COLUMN error TEXT;
    """,
    # 17: Kea (DHCP) on a node
    """
    ALTER TABLE nodes ADD COLUMN dhcp INTEGER NOT NULL DEFAULT 0;   -- 1 once LiteBlox set Kea up there
    ALTER TABLE nodes ADD COLUMN kea_hooks_dir TEXT;               -- as the agent reported it (per architecture)
    ALTER TABLE nodes ADD COLUMN dhcp_files TEXT;                  -- JSON {role: sha256} of the last Kea commit
    ALTER TABLE nodes ADD COLUMN dhcp_drift TEXT;                  -- JSON [role, ...] changed outside LiteBlox; NULL: none
    """,
    # 18: DHCPv4 subnets, pools and options
    """
    ALTER TABLE nodes ADD COLUMN dhcp_interfaces TEXT NOT NULL DEFAULT '[]';   -- JSON [name, ...] Kea serves on
    CREATE TABLE dhcp4_settings (
        id             INTEGER PRIMARY KEY CHECK (id = 1),
        valid_lifetime INTEGER,                       -- NULL: Kea's default
        renew_timer    INTEGER,
        rebind_timer   INTEGER,
        options        TEXT NOT NULL DEFAULT '{}',    -- JSON {routers, dns, domain, search, ntp}
        extra_options  TEXT NOT NULL DEFAULT '[]',    -- JSON [option-data, ...] as Kea takes them
        authoritative  INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO dhcp4_settings (id) VALUES (1);
    CREATE TABLE dhcp4_subnets (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,   -- Kea's subnet-id: never reused
        prefix         TEXT NOT NULL UNIQUE,
        interface      TEXT NOT NULL,                 -- the serving node's interface on that network
        pools          TEXT NOT NULL DEFAULT '',      -- one "a - b" or CIDR per line
        options        TEXT NOT NULL DEFAULT '{}',
        extra_options  TEXT NOT NULL DEFAULT '[]',
        extra          TEXT NOT NULL DEFAULT '{}',    -- JSON object merged into the subnet
        valid_lifetime INTEGER,
        renew_timer    INTEGER,
        rebind_timer   INTEGER,
        comment        TEXT NOT NULL DEFAULT '',
        created_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    # 19: DDNS (clients registered in DNS) and node clocks
    """
    ALTER TABLE dhcp4_settings ADD COLUMN ddns_key_id INTEGER REFERENCES tsig_keys(id);  -- NULL: no DDNS
    ALTER TABLE dhcp4_subnets ADD COLUMN ddns INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE dhcp4_subnets ADD COLUMN ddns_zone_id INTEGER REFERENCES zones(id);
    ALTER TABLE dhcp4_subnets ADD COLUMN ddns_suffix TEXT NOT NULL DEFAULT '';           -- '': the zone itself
    ALTER TABLE nodes ADD COLUMN clock_skew REAL;           -- seconds, the node's clock minus LiteBlox's
    ALTER TABLE nodes ADD COLUMN clock_synced INTEGER;      -- NTP synchronized (1/0), NULL: unknown
    ALTER TABLE nodes ADD COLUMN clock_checked_at TEXT;
    """,
    # 20: DHCPv4 reservations
    """
    CREATE TABLE dhcp4_reservations (
        id          INTEGER PRIMARY KEY,
        subnet_id   INTEGER NOT NULL REFERENCES dhcp4_subnets(id) ON DELETE CASCADE,
        hw_address  TEXT NOT NULL,                 -- aa:bb:cc:dd:ee:ff
        ip_address  TEXT NOT NULL,
        hostname    TEXT NOT NULL DEFAULT '',      -- '': the client's own name
        options     TEXT NOT NULL DEFAULT '{}',
        comment     TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (subnet_id, hw_address),
        UNIQUE (subnet_id, ip_address)
    );
    """,
    # 21: the DHCP failover pair (Kea HA, hot-standby)
    """
    CREATE TABLE dhcp4_ha (
        id               INTEGER PRIMARY KEY CHECK (id = 1),
        primary_node_id  INTEGER REFERENCES nodes(id) ON DELETE SET NULL,   -- NULL: no pair
        standby_node_id  INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
        primary_address  TEXT,                         -- the peer link: where each listens for its partner
        standby_address  TEXT,
        port             INTEGER NOT NULL DEFAULT 8001
    );
    INSERT INTO dhcp4_ha (id) VALUES (1);
    ALTER TABLE nodes ADD COLUMN kea_tls TEXT;           -- JSON {address, cert, key, ca}: its peer-link certificate
    ALTER TABLE nodes ADD COLUMN dhcp_ha_state TEXT;     -- as kea-dhcp4 last reported it (hot-standby, partner-down, ...)
    ALTER TABLE nodes ADD COLUMN dhcp_ha_checked_at TEXT;
    """,
    # 22: re-adopting nodes another LiteBlox managed (its data lost): their agent says LiteBlox generated
    # their BIND config, but this one doesn't manage them
    """
    ALTER TABLE nodes ADD COLUMN other_liteblox INTEGER NOT NULL DEFAULT 0;
    """,
    # 23: API tokens (3.1): per user, read-only or full; only a hash of the secret is kept
    """
    CREATE TABLE api_tokens (
        id           INTEGER PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name         TEXT NOT NULL,
        prefix       TEXT NOT NULL,                 -- the first characters, to tell tokens apart
        token_hash   TEXT NOT NULL UNIQUE,          -- sha256 of the whole token
        scope        TEXT NOT NULL CHECK (scope IN ('read', 'full')),
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        created_by   TEXT,
        expires_at   TEXT,                          -- NULL: never
        last_used_at TEXT,
        last_used_ip TEXT,
        UNIQUE (user_id, name)
    );
    """,
    # 24: time (chrony) on the nodes (3.2): one set of sources for every node; each node may serve time
    """
    CREATE TABLE ntp_settings (
        id      INTEGER PRIMARY KEY CHECK (id = 1),
        sources TEXT NOT NULL DEFAULT '[]'        -- JSON [{kind, address, iburst, prefer, nts, minpoll, maxpoll}]
    );
    INSERT INTO ntp_settings (id) VALUES (1);
    ALTER TABLE nodes ADD COLUMN ntp INTEGER NOT NULL DEFAULT 0;            -- 1 once LiteBlox set chrony up there
    ALTER TABLE nodes ADD COLUMN ntp_serve INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE nodes ADD COLUMN ntp_allow TEXT NOT NULL DEFAULT '[]';      -- JSON [network, ...] it serves time to
    ALTER TABLE nodes ADD COLUMN ntp_local INTEGER;                         -- local stratum when upstreams fail; NULL: off
    ALTER TABLE nodes ADD COLUMN ntp_files TEXT;                            -- JSON {role: sha256} of the last commit
    ALTER TABLE nodes ADD COLUMN ntp_drift TEXT;                            -- JSON [role, ...] changed outside LiteBlox
    ALTER TABLE nodes ADD COLUMN ntp_state TEXT;                            -- JSON {synced, reference, stratum, offset}
    """,
    # 25: the Dashboard's graphs (3.3): node figures and active leases, sampled by the health check every minute;
    # rows older than two days are rolled up into 15-minute averages (stats.py)
    """
    CREATE TABLE samples (
        id        INTEGER PRIMARY KEY,
        node_id   INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
        subnet_id INTEGER REFERENCES dhcp4_subnets(id) ON DELETE CASCADE,
        metric    TEXT NOT NULL,            -- load1, mem_used_pct, disk_used_pct, dns_qpm; leases_active, leases_in_pool
        at        INTEGER NOT NULL,         -- unix time
        period    INTEGER NOT NULL DEFAULT 60 CHECK (period IN (60, 900)),
        value     REAL NOT NULL
    );
    CREATE INDEX samples_series ON samples (metric, node_id, subnet_id, at);
    CREATE INDEX samples_age ON samples (period, at);
    """,
    # 26: whether Kea listens for DHCP (3.3): status-get's sockets when not ready, or why kea-dhcp4 doesn't answer
    """
    ALTER TABLE nodes ADD COLUMN dhcp_sockets TEXT;     -- JSON {status: retrying|failed|down, errors: [...]}; NULL: fine
    """,
    # 27: every static zone is kept sorted (3.3.1; zones.sorted now means "checked to sort"), and notes kept in
    # LiteBlox only, which also get the comment lines sorting takes out of a zone file
    """
    ALTER TABLE zones ADD COLUMN notes TEXT NOT NULL DEFAULT '';
    """,
    # 28: IPAM (3.4): networks (their nesting is worked out from the prefixes, never stored), named ranges in a
    # network (DHCP pools aren't copied here: they come from the DHCP subnets), and notes for addresses that have
    # nothing else to hold a comment (a free address kept for later, a name in a dynamic zone)
    """
    CREATE TABLE ipam_networks (
        id            INTEGER PRIMARY KEY,
        prefix        TEXT NOT NULL UNIQUE,         -- 192.168.0.0/24, canonical
        name          TEXT NOT NULL DEFAULT '',
        comment       TEXT NOT NULL DEFAULT '',
        sweep         TEXT NOT NULL DEFAULT 'off' CHECK (sweep IN ('off', 'hourly', 'daily')),
        sweep_node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
        swept_at      TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE ipam_ranges (
        id         INTEGER PRIMARY KEY,
        network_id INTEGER NOT NULL REFERENCES ipam_networks(id) ON DELETE CASCADE,
        first      TEXT NOT NULL,
        last       TEXT NOT NULL,
        kind       TEXT NOT NULL DEFAULT 'static' CHECK (kind IN ('static', 'infrastructure', 'reserved', 'other')),
        name       TEXT NOT NULL DEFAULT '',
        comment    TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX ipam_ranges_network ON ipam_ranges (network_id);
    -- each node's own IPv4 networks (from its agent's status, every minute): IPAM's Check and probes go
    -- through a node on the address's network
    ALTER TABLE nodes ADD COLUMN networks TEXT NOT NULL DEFAULT '[]';
    CREATE TABLE ipam_notes (
        ip         TEXT PRIMARY KEY,
        note       TEXT NOT NULL,
        username   TEXT,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    # 29: what the nodes see on their networks (3.4): each address's MACs from the nodes' neighbour tables, kept
    # for keep_days, the MAC changes (flapping: two devices on one address), the flapping an admin has seen, and
    # IPAM's settings (the vendor list's state too). Times are unix seconds.
    """
    CREATE TABLE ipam_seen (
        ip         TEXT NOT NULL,
        mac        TEXT NOT NULL,                   -- lowercase, colons
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,                -- when a node last had it confirmed: never moves back
        node_id    INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
        source     TEXT NOT NULL DEFAULT 'neigh' CHECK (source IN ('neigh', 'sweep', 'probe')),
        PRIMARY KEY (ip, mac)
    );
    CREATE INDEX ipam_seen_mac ON ipam_seen (mac);
    CREATE TABLE ipam_changes (
        id      INTEGER PRIMARY KEY,
        ip      TEXT NOT NULL,
        at      INTEGER NOT NULL,
        old_mac TEXT NOT NULL,
        new_mac TEXT NOT NULL
    );
    CREATE INDEX ipam_changes_ip ON ipam_changes (ip, at);
    CREATE TABLE ipam_acks (
        ip       TEXT PRIMARY KEY,
        acked_at INTEGER NOT NULL,
        username TEXT
    );
    CREATE TABLE ipam_settings (
        id             INTEGER PRIMARY KEY CHECK (id = 1),
        keep_days      INTEGER NOT NULL DEFAULT 7,
        flap_changes   INTEGER NOT NULL DEFAULT 3,
        flap_minutes   INTEGER NOT NULL DEFAULT 10,
        oui_checked_at INTEGER,                     -- the last fetch tried
        oui_error      TEXT
    );
    INSERT INTO ipam_settings (id) VALUES (1);
    """,
    # 30: devices (3.4): a label and a comment per MAC; name-only reservations (ip_address '': Kea gives the client
    # a pool address and registers the reserved name), so the address is unique per subnet only when there is one;
    # MACs expected on one address (two NICs answering ARP, a bond, a repeater): changes between them aren't flapping
    """
    CREATE TABLE devices (
        id         INTEGER PRIMARY KEY,
        mac        TEXT NOT NULL UNIQUE,            -- lowercase, colons
        label      TEXT NOT NULL DEFAULT '',
        comment    TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE dhcp4_reservations_v30 (
        id          INTEGER PRIMARY KEY,
        subnet_id   INTEGER NOT NULL REFERENCES dhcp4_subnets(id) ON DELETE CASCADE,
        hw_address  TEXT NOT NULL,                 -- aa:bb:cc:dd:ee:ff
        ip_address  TEXT NOT NULL,                 -- '': name-only
        hostname    TEXT NOT NULL DEFAULT '',      -- '': the client's own name
        options     TEXT NOT NULL DEFAULT '{}',
        comment     TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (subnet_id, hw_address)
    );
    INSERT INTO dhcp4_reservations_v30 SELECT id, subnet_id, hw_address, ip_address, hostname, options, comment,
        created_at FROM dhcp4_reservations;
    DROP TABLE dhcp4_reservations;
    ALTER TABLE dhcp4_reservations_v30 RENAME TO dhcp4_reservations;
    CREATE UNIQUE INDEX dhcp4_reservations_ip ON dhcp4_reservations (subnet_id, ip_address) WHERE ip_address != '';
    ALTER TABLE ipam_acks ADD COLUMN expected TEXT;              -- JSON list of MACs; NULL: a plain acknowledgement
    ALTER TABLE ipam_acks ADD COLUMN reason TEXT NOT NULL DEFAULT '';
    """,
    # 31: next free (3.4): addresses held for a few minutes between "next free" and using them (a block shares a
    # hold_id), what "assign" created (so "unassign" removes exactly that), and each node's own IPv4 addresses
    """
    CREATE TABLE ipam_holds (
        ip         TEXT PRIMARY KEY,
        hold_id    TEXT NOT NULL,
        expires_at INTEGER NOT NULL,                -- unix seconds
        username   TEXT,
        note       TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX ipam_holds_id ON ipam_holds (hold_id);
    CREATE TABLE ipam_assignments (
        ip         TEXT PRIMARY KEY,
        grp        TEXT NOT NULL DEFAULT '',         -- the optional group tag, for unassigning a lab at once
        kind       TEXT NOT NULL CHECK (kind IN ('static', 'reservation')),
        name       TEXT NOT NULL,                    -- the fqdn (static) or the reservation's hostname
        zone       TEXT,                             -- where the A record went (static, or a reservation without DDNS)
        subnet_id  INTEGER,                          -- a reservation's subnet
        mac        TEXT,                             -- a reservation's MAC
        comment    TEXT NOT NULL DEFAULT '',
        username   TEXT,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX ipam_assignments_grp ON ipam_assignments (grp);
    ALTER TABLE nodes ADD COLUMN addresses TEXT NOT NULL DEFAULT '[]';
    """,
    # 32: modules (4.0): which of DNS, DHCP, Time and IPAM this install runs. An install that already has users keeps
    # all four, chosen; a fresh one starts with all four but unchosen, and its first Dashboard asks.
    """
    CREATE TABLE modules (
        id        INTEGER PRIMARY KEY CHECK (id = 1),
        dns       INTEGER NOT NULL DEFAULT 1,
        dhcp      INTEGER NOT NULL DEFAULT 1,
        ntp       INTEGER NOT NULL DEFAULT 1,
        ipam      INTEGER NOT NULL DEFAULT 1,
        chosen_at TEXT
    );
    INSERT INTO modules (id, chosen_at)
        VALUES (1, CASE WHEN EXISTS (SELECT 1 FROM users) THEN datetime('now') END);
    """,
    # 33: nodes without BIND (4.0): scanner nodes (only the agent, for IPAM) and DHCP/Time-only nodes
    """
    ALTER TABLE nodes ADD COLUMN bind INTEGER NOT NULL DEFAULT 1;
    """,
    # 34: IPAM without DNS (4.0): IPAM records (kind 'ipam': a name kept in IPAM only, an optional MAC and a
    # comment), the PTR names a resolver gives the used addresses (rDNS), and that resolver
    """
    CREATE TABLE ipam_assignments_v34 (
        ip         TEXT PRIMARY KEY,
        grp        TEXT NOT NULL DEFAULT '',
        kind       TEXT NOT NULL CHECK (kind IN ('static', 'reservation', 'ipam')),
        name       TEXT NOT NULL,
        zone       TEXT,
        subnet_id  INTEGER,
        mac        TEXT,                             -- a reservation's MAC, or an IPAM record's (optional)
        comment    TEXT NOT NULL DEFAULT '',
        username   TEXT,
        created_at INTEGER NOT NULL
    );
    INSERT INTO ipam_assignments_v34 SELECT ip, grp, kind, name, zone, subnet_id, mac, comment, username, created_at
        FROM ipam_assignments;
    DROP TABLE ipam_assignments;
    ALTER TABLE ipam_assignments_v34 RENAME TO ipam_assignments;
    CREATE INDEX ipam_assignments_grp ON ipam_assignments (grp);
    CREATE TABLE ipam_ptr (
        ip           TEXT PRIMARY KEY,
        name         TEXT NOT NULL DEFAULT '',       -- '': the resolver has no PTR for it
        looked_up_at INTEGER NOT NULL,               -- unix seconds
        error        TEXT                            -- the lookup failed (a timeout, SERVFAIL): retried sooner
    );
    ALTER TABLE ipam_settings ADD COLUMN resolver TEXT NOT NULL DEFAULT '';     -- address[:port]; '': no lookups
    ALTER TABLE ipam_settings ADD COLUMN ptr_hours INTEGER NOT NULL DEFAULT 24;
    """,
    # 35: DHCP without LiteBlox's DNS (4.0): where Kea registers clients: through LiteBlox's DNS primary (as
    # before, with a key from tsig_keys), at another DNS server (its address, port and key, kept here: never
    # rendered into BIND), or not at all; and a subnet's reverse zones there, when not derived from its prefix
    """
    ALTER TABLE dhcp4_settings ADD COLUMN ddns_mode TEXT NOT NULL DEFAULT 'off'
        CHECK (ddns_mode IN ('liteblox', 'external', 'off'));
    UPDATE dhcp4_settings SET ddns_mode = 'liteblox' WHERE ddns_key_id IS NOT NULL;
    ALTER TABLE dhcp4_settings ADD COLUMN ddns_server TEXT NOT NULL DEFAULT '';
    ALTER TABLE dhcp4_settings ADD COLUMN ddns_port INTEGER NOT NULL DEFAULT 53;
    ALTER TABLE dhcp4_settings ADD COLUMN ddns_external_key TEXT;       -- JSON {name, algorithm, secret}
    ALTER TABLE dhcp4_subnets ADD COLUMN ddns_reverse TEXT NOT NULL DEFAULT '';   -- zone names; '': derived
    """,
    # 36: stale DHCP names (4.1): per name Kea registered (one with a DHCID), the last lease expiry LiteBlox saw,
    # or when it first saw the name without a lease, so a name's age is known after Kea forgets the lease;
    # reclaiming them per dynamic zone (off by default; after: seconds, NULL = the longest lease time); and
    # IPAM's say: keep a name while the nodes still see its address
    """
    CREATE TABLE ddns_names (
        name        TEXT PRIMARY KEY,                -- the fqdn, lowercase, no trailing dot
        address     TEXT,
        last_expiry INTEGER,                         -- when its newest lease seen ends (unix time)
        noticed_at  INTEGER                          -- first seen without a lease (when last_expiry is unknown)
    );
    ALTER TABLE zones ADD COLUMN reclaim INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE zones ADD COLUMN reclaim_after INTEGER;
    ALTER TABLE zones ADD COLUMN reclaim_checked_at INTEGER;
    ALTER TABLE zones ADD COLUMN reclaim_note TEXT;  -- the last pass's outcome, when it held back
    ALTER TABLE ipam_settings ADD COLUMN keep_seen_names INTEGER NOT NULL DEFAULT 1;
    """,
    # v37 (4.2): how long a seen address counts as in use, apart from how long it's kept (keep_days)
    """
    ALTER TABLE ipam_settings ADD COLUMN seen_hours INTEGER NOT NULL DEFAULT 24;
    """,
    # v38 (4.4): a Wi-Fi repeater's MAC, which stands in on the LAN for the devices connected through it: seen on
    # an address, it's no sign of another device there
    """
    ALTER TABLE devices ADD COLUMN repeater INTEGER NOT NULL DEFAULT 0;
    """,
    # v39 (4.5): the install layout Repair last put on a node (its agent reports it): a node on the image's own
    # revision has the root installer, so its agent can be upgraded over mTLS
    """
    ALTER TABLE nodes ADD COLUMN install_rev INTEGER;
    """,
    # v40 (4.6): built-in HTTPS, opt-in, on its own port beside plain HTTP. The certificate is in <data>/tls;
    # fingerprint is what LiteBlox last wrote there (a different one was renewed outside LiteBlox), and listening,
    # port, serving and error are what the running server found
    """
    CREATE TABLE https_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        enabled INTEGER NOT NULL DEFAULT 0,
        https_only INTEGER NOT NULL DEFAULT 0,
        names TEXT NOT NULL DEFAULT '',
        source TEXT,
        fingerprint TEXT,
        listening INTEGER NOT NULL DEFAULT 0,
        port INTEGER,
        serving TEXT,
        error TEXT,
        updated_at TEXT,
        updated_by TEXT
    );
    INSERT INTO https_settings (id) VALUES (1);
    """,
    # v41 (4.8): the standby of a failover pair may name its interfaces differently: {primary's name: standby's},
    # matched by network. Subnets keep the primary's names; empty means the same names on both
    """
    ALTER TABLE dhcp4_ha ADD COLUMN interface_map TEXT NOT NULL DEFAULT '{}';
    """,
    # v42 (4.8): Kea's and chrony's versions as the node last reported them, for what each one reads: Kea before
    # 2.5 (Ubuntu 24.04's 2.4) spells a logger's output_options with an underscore, chrony before 4.6 has no
    # leapseclist
    """
    ALTER TABLE nodes ADD COLUMN kea_version TEXT;
    ALTER TABLE nodes ADD COLUMN chrony_version TEXT;
    """,
]


def connect(path):
    # one connection per request; FastAPI may run the dependency and the
    # endpoint on different threadpool threads, which is safe here
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 5000')
    return conn


def schema_version(conn):
    return conn.execute('PRAGMA user_version').fetchone()[0]


class SchemaTooNew(RuntimeError):
    """The database was migrated by a newer LiteBlox: this older code would run on tables it doesn't know."""


def migrate(path):
    # holds password hashes; sqlite gives its -wal/-shm files the same mode
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    conn = connect(path)
    try:
        conn.execute('PRAGMA journal_mode = WAL')
        current = schema_version(conn)
        if current > len(MIGRATIONS):
            from .version import __version__
            raise SchemaTooNew(f'the database ({path}) is schema v{current}, written by a newer LiteBlox; '
                               f'{__version__} knows up to v{len(MIGRATIONS)}. Run the newer image again, or restore '
                               'the copy of the data from before the upgrade')
        for version, sql in enumerate(MIGRATIONS[current:], start=current + 1):
            conn.executescript(f'BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;')
        return schema_version(conn)
    finally:
        conn.close()


def get_db(request: Request):
    conn = connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def audit(conn, username, action, detail=None):
    with conn:
        conn.execute('INSERT INTO audit (username, action, detail) VALUES (?, ?, ?)',
                     (username, action, detail))
