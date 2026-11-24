"""HTTPS client for liteblox-agent, authenticated both ways with the LiteBlox CA."""

import ssl

import httpx

AGENT_PORT = 8530


class AgentError(Exception):
    """The agent answered with an error, or could not be reached (status None)."""

    def __init__(self, status, message, details=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.details = details or {}


class AgentClient:
    def __init__(self, host, pki, port=AGENT_PORT, timeout=30.0):
        ctx = ssl.create_default_context(cafile=str(pki.ca_cert_path))
        ctx.load_cert_chain(str(pki.client_cert_path), str(pki.client_key_path))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        netloc = f'[{host}]' if ':' in host else host
        self.base_url = f'https://{netloc}:{port}'
        self.http = httpx.Client(base_url=self.base_url, verify=ctx, timeout=timeout)

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _request(self, method, path, **kwargs):
        try:
            r = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise AgentError(None, f'cannot reach agent at {self.base_url}: {e}') from e
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {'error': r.text}
            message = body.pop('error', f'HTTP {r.status_code}')
            raise AgentError(r.status_code, message, body)
        return r

    def _zone_path(self, zone, action=''):
        name = zone.rstrip('.').lower()
        return f'/zones/{name}' + (f'/{action}' if action else '')

    def status(self):
        return self._request('GET', '/status').json()

    def stats(self):
        return self._request('GET', '/stats').json()

    def upgrade_agent(self, version, digest, source):
        """Stage a new agent; the agent restarts and its root installer puts it in place (agent 4.5+)."""
        return self._request('POST', '/agent/upgrade', json={'version': version, 'sha256': digest,
                                                             'source': source}).json()

    def neigh(self, family=4):
        """The node's IPv4 (or IPv6, agent 6.0+) neighbour table: [{ip, mac, dev, state, used, confirmed, updated,
        probes}] (agent 3.4+)."""
        params = {'family': '6'} if family == 6 else None
        return self._request('GET', '/neigh', params=params).json()['neighbours']

    def probe(self, addresses, interval_ms=100, wait=2.0):
        """Ping addresses on the node's own networks and read their neighbour entries (agent 3.4+):
        {method, elapsed, results: {ip: {replied, rtt_ms, state, mac, confirmed}}}."""
        return self._request('POST', '/probe', json={'addresses': list(addresses), 'interval_ms': interval_ms,
                                                     'wait': wait}, timeout=60.0).json()

    def config(self, secrets=False, files=False):
        params = {**({'secrets': '1'} if secrets else {}), **({'files': '1'} if files else {})}
        return self._request('GET', '/config', params=params or None).json()

    def get_zone(self, zone, sync=False, freeze=False):
        """sync: a dynamic zone's journal written into its file first; freeze: and updates held until the next
        config commit or abort (or thaw_zone)."""
        params = {'freeze': '1'} if freeze else {'sync': '1'} if sync else None
        return self._request('GET', self._zone_path(zone), params=params).json()

    def thaw_zone(self, zone):
        return self._request('POST', self._zone_path(zone, 'thaw'), json={}).json()

    def stage_zone(self, zone, content, base_sha256):
        return self._request('POST', self._zone_path(zone, 'stage'),
                             json={'content': content, 'base_sha256': base_sha256}).json()

    def commit_zone(self, zone, stage_id):
        return self._request('POST', self._zone_path(zone, 'commit'), json={'stage_id': stage_id}).json()

    def abort_zone(self, zone, stage_id):
        return self._request('POST', self._zone_path(zone, 'abort'), json={'stage_id': stage_id}).json()

    def check_config(self, files):
        return self._request('POST', '/config/check', json={'files': files}).json()

    def stage_config(self, files, zone_files=None, takeover=False, retire=None):
        return self._request('POST', '/config/stage', json={
            'files': files, 'zone_files': zone_files or {}, 'takeover': takeover, 'retire': retire or []}).json()

    def commit_config(self, stage_id):
        return self._request('POST', '/config/commit', json={'stage_id': stage_id}).json()

    def abort_config(self, stage_id):
        return self._request('POST', '/config/abort', json={'stage_id': stage_id}).json()

    def rollback_config(self):
        return self._request('POST', '/config/rollback', json={}).json()

    # Kea (DHCP): the same stage → commit → rollback shape as /config, for kea-dhcp4.conf / kea-dhcp-ddns.conf

    def check_dhcp(self, files):
        return self._request('POST', '/dhcp/check', json={'files': files}).json()

    def stage_dhcp(self, files):
        return self._request('POST', '/dhcp/stage', json={'files': files}).json()

    def commit_dhcp(self, stage_id):
        return self._request('POST', '/dhcp/commit', json={'stage_id': stage_id}).json()

    def abort_dhcp(self, stage_id):
        return self._request('POST', '/dhcp/abort', json={'stage_id': stage_id}).json()

    def rollback_dhcp(self):
        return self._request('POST', '/dhcp/rollback', json={}).json()

    def dhcp_files(self, secrets=False):
        """secrets: D2's TSIG secrets unmasked (re-adopt only; never shown)."""
        return self._request('GET', '/dhcp/files', params={'secrets': '1'} if secrets else None).json()['files']

    def dhcp_command(self, service, command, arguments=None):
        body = {'service': service, 'command': command, **({'arguments': arguments} if arguments is not None else {})}
        return self._request('POST', '/dhcp/command', json=body).json()

    # chrony (time): the same shape again, for chrony.conf

    def check_ntp(self, files):
        return self._request('POST', '/ntp/check', json={'files': files}).json()

    def stage_ntp(self, files):
        return self._request('POST', '/ntp/stage', json={'files': files}).json()

    def commit_ntp(self, stage_id):
        # the agent waits for chrony to restart on the new file
        return self._request('POST', '/ntp/commit', json={'stage_id': stage_id}, timeout=60.0).json()

    def abort_ntp(self, stage_id):
        return self._request('POST', '/ntp/abort', json={'stage_id': stage_id}).json()

    def rollback_ntp(self):
        return self._request('POST', '/ntp/rollback', json={}, timeout=60.0).json()

    def ntp_files(self):
        return self._request('GET', '/ntp/files').json()['files']

    def backup(self, include_keys=True):
        """(tar.gz bytes, manifest hash header)."""
        r = self._request('GET', '/backup', params={'keys': '1' if include_keys else '0'},
                          timeout=120.0)
        return r.content, r.headers.get('X-Manifest-SHA256')
