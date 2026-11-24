"""Recent activity: jobs and the audit log's changes, with labels people read."""

# every action db.audit records (tests/test_activity.py checks the callers against this list)
LABELS = {
    'acl_add': 'Added an ACL', 'acl_change': 'Changed an ACL', 'acl_delete': 'Deleted an ACL',
    'backup': 'Backed up', 'backup_download': 'Downloaded a backup', 'backup_settings': 'Changed backup settings',
    'demote_dismiss': 'Dismissed a demote report', 'demote_reapply': 'Put back records from a demote report',
    'dhcp_apply': 'Changed DHCP', 'dhcp_lease_delete': 'Deleted a lease',
    'dhcp6_ra_auto_off': 'Turned router advertisements off (the development time limit)',
    'dhcp_reservation_comment': "Changed a reservation's comment",
    'draft_discard': 'Discarded a draft',
    'drift_import': "Kept a node's own config", 'drift_overwrite': "Overwrote a node's changed config",
    'history_restore': 'Restored a zone version', 'import_v1': 'Imported zoneedit history',     # gone in 3.3.4; older audit rows keep it
    'ipam_network_add': 'Added a network to IPAM', 'ipam_network_delete': 'Took a network out of IPAM',
    'ipam_network_edit': 'Changed an IPAM network', 'ipam_note': 'Changed an address note',
    'ipam_range_add': 'Added an IPAM range', 'ipam_range_delete': 'Deleted an IPAM range',
    'ipam_range_edit': 'Changed an IPAM range',
    'ipam_ack': 'Acknowledged a flapping address', 'ipam_forget': 'Forgot a device seen',
    'ipam_settings': 'Changed IPAM settings', 'modules': 'Changed the modules', 'ipam_vendors': 'Fetched the MAC vendor list',
    'ipam_expect': 'Marked MACs as expected on an address', 'ipam_unmute': 'Unmuted an address\'s expected MACs',
    'ipam_device': 'Changed a device\'s label', 'ipam_assign': 'Assigned addresses',
    'ipam_unassign': 'Unassigned addresses', 'ipam_sweep': 'Started a network sweep',
    'ipam_name': 'Named an address in IPAM', 'ipam_name_delete': "Removed an address's IPAM name",
    'key_add': 'Added a TSIG key', 'key_delete': 'Deleted a TSIG key', 'key_grant': 'Granted a key a zone',
    'key_revoke': "Revoked a key's grant", 'key_rotate': "Replaced a key's secret",
    'https_allow_http': 'Allowed plain HTTP again', 'https_disable': 'Turned HTTPS off',
    'https_enable': 'Turned HTTPS on', 'https_generate': 'Made a self-signed HTTPS certificate',
    'https_import': 'Imported an HTTPS certificate', 'https_only': 'Made LiteBlox HTTPS only',
    'login': 'Logged in', 'login_blocked': 'Refused a login (too many failures)', 'login_failed': 'Failed login',
    'logout': 'Logged out',
    'node_add': 'Added a node', 'node_bootstrap': 'Set up or repaired a node',
    'node_agent_upgrade': "Upgraded a node's agent",
    'node_dns_address': "Changed a node's DNS address", 'node_overwrite': "Wrote LiteBlox's config over a node's",
    'node_primary': 'Made a node the primary', 'node_promote': 'Promoted a node', 'node_readopt': 'Re-adopted nodes',
    'node_remove': 'Removed a node', 'node_rewrite': "Wrote a node's BIND config again",
    'node_settings': 'Changed server settings', 'node_takeover': 'Took over a node',
    'node_update': "Changed a node's address or host key",
    'ns_add': 'Added a nameserver', 'ns_delete': 'Removed a nameserver',
    'ntp_apply': 'Changed time sync', 'ntp_sources': 'Changed the time sources',
    'password_change': 'Changed a password',
    'ptr_drop': 'Dropped a PTR change', 'ptr_retry': 'Retried a PTR change', 'ptr_sync': 'Synced PTR records',
    'publish': 'Published a zone',
    'address_move': 'Moved an address', 'ddns_delete': 'Deleted stale DHCP names', 'ddns_reclaim': 'Reclaimed stale DHCP names', 'zone_reclaim': 'Changed reclaiming of stale DHCP names', 'record_add': 'Added a record', 'record_batch': 'Changed records in a batch (API)', 'record_bulk': 'Changed records in bulk', 'record_many': 'Added many records', 'record_delete': 'Deleted a record', 'record_edit': 'Changed a record',
    'soa_edit': "Changed a zone's SOA",
    'token_add': 'Created an API token', 'token_revoke': 'Revoked an API token',
    'user_add': 'Added a user', 'user_delete': 'Deleted a user', 'user_password_reset': 'Reset a password',
    'user_role': "Changed a user's role",
    'zone_add_node': 'Added a node to a zone', 'zone_auto_ptr': 'Changed PTR syncing', 'zone_create': 'Created a zone',
    'zone_delete': 'Deleted a zone', 'zone_dynamic': 'Changed dynamic updates', 'zone_forwarders': 'Changed forwarders',
    'zone_raw_edit': "Edited a zone's text", 'zone_remove_node': 'Removed a node from a zone',
    'zone_notes': "Changed a zone's notes", 'zone_settings': 'Changed zone settings',
    'zone_sorted': 'Changed record order',     # before 3.3.1, when sorting was per zone
}
QUIET = ('login', 'logout', 'login_failed', 'login_blocked')     # left out of the Dashboard's activity


ACRONYMS = {'acl': 'ACL', 'acls': 'ACLs', 'bind': 'BIND', 'dhcp': 'DHCP', 'dns': 'DNS', 'ipam': 'IPAM', 'ntp': 'NTP', 'tsig': 'TSIG'}


def label(action):
    return LABELS.get(action, action.replace('_', ' ').capitalize())


def job_label(kind):
    """A job's kind for people: 'bind config' → 'BIND config', 'publish' → 'Publish'."""
    words = [ACRONYMS.get(w.lower(), w) for w in (kind or '').split()]
    if words and words[0] == words[0].lower():
        words[0] = words[0].capitalize()
    return ' '.join(words)


def recent(conn, limit=8):
    """The newest jobs and audited changes (logins left out), newest first:
    [{at, kind: job|change, label, detail, who, status, link}].

    A change a job recorded (same user, written while it ran) shows as the job, which links to its log.
    Scheduled jobs (no user: the hourly IPAM sweeps) show only when they fail, so they don't bury what people
    did; LiteBlox's own fixes (user 'liteblox': a demotion, Kea's recovery) always show. The Jobs page has them all."""
    jobs = conn.execute('SELECT j.*, n.name AS node, z.name AS zone FROM jobs j '
                        'LEFT JOIN nodes n ON n.id = j.node_id LEFT JOIN zones z ON z.id = j.zone_id '
                        "WHERE j.username IS NOT NULL OR j.status = 'failed' "
                        'ORDER BY j.id DESC LIMIT ?', (limit * 3,)).fetchall()
    out = [{'at': j['created_at'], 'kind': 'job', 'label': f"#{j['id']} {job_label(j['kind'])}",
            'detail': j['node'] or j['zone'] or '', 'who': j['username'] or '', 'status': j['status'],
            'link': f"/jobs/{j['id']}"} for j in jobs[:limit]]

    def in_a_job(a):
        return any(j['username'] == a['username'] and j['created_at'] <= a['at'] <= (j['finished_at'] or a['at'])
                   for j in jobs)
    marks = ','.join('?' * len(QUIET))
    for a in conn.execute(f'SELECT * FROM audit WHERE action NOT IN ({marks}) ORDER BY id DESC LIMIT ?',
                          (*QUIET, limit * 3)):
        if not in_a_job(a):
            out.append({'at': a['at'], 'kind': 'change', 'label': label(a['action']), 'detail': a['detail'] or '',
                        'who': a['username'] or '', 'status': None, 'link': None})
    out.sort(key=lambda r: r['at'], reverse=True)
    return out[:limit]
