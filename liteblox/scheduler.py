"""Daily at [backups] backup_at (the container's local time, from TZ): node config backups, then
snapshots of dynamic zones into their history. Every minute: the node health check. Every day (and a minute
after starting): IPAM's MAC vendor list, fetched again when it's a week old."""

import asyncio
import logging
from datetime import datetime, timedelta

from .backups import service as backups
from .dns import dynamic
from .nodes import health as node_health

log = logging.getLogger(__name__)
HEALTH_EVERY = 60
DAILY = 86400


def seconds_until(hhmm, now=None):
    now = now or datetime.now()
    hour, minute = map(int, hhmm.split(':'))
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


async def run(settings):
    if not settings.backups.backup_at:
        log.info('scheduled backups disabled (backup_at is empty)')
        return
    loop = asyncio.get_running_loop()
    while True:
        delay = seconds_until(settings.backups.backup_at)
        log.info('next scheduled backup in %.0f minutes', delay / 60)
        await asyncio.sleep(delay)
        try:
            await loop.run_in_executor(None, lambda: backups.backup_all(
                settings, 'scheduled', 'scheduler', log=lambda line: log.info('backup %s', line)))
        except Exception:
            log.exception('scheduled backup run failed')
        try:       # changes DHCP, ACME and nsupdate made to dynamic zones go into their history
            await loop.run_in_executor(None, lambda: dynamic.snapshot_all(
                settings, log=lambda line: log.info('snapshot %s', line)))
        except Exception:
            log.exception('dynamic zone snapshots failed')


async def health(settings):
    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(HEALTH_EVERY)
        try:
            await loop.run_in_executor(None, lambda: node_health.check_all(
                settings, log=lambda line: log.debug('health %s', line)))
        except Exception:
            log.exception('node health check failed')


async def ipam_daily(settings):
    from . import db
    from .ipam import oui
    loop = asyncio.get_running_loop()
    await asyncio.sleep(HEALTH_EVERY)

    def refresh():
        conn = db.connect(settings.db_path)
        try:
            return oui.refresh(settings, conn)
        finally:
            conn.close()
    while True:
        try:
            log.info('ipam %s', await loop.run_in_executor(None, refresh))
        except Exception:
            log.exception('IPAM vendor list check failed')
        await asyncio.sleep(DAILY)


async def ddns_reclaim(settings):
    """Every 10 minutes: the dynamic zones whose stale DHCP names are reclaimed and are due a check (hourly)."""
    from . import db
    from .dns import reclaim
    loop = asyncio.get_running_loop()
    await asyncio.sleep(HEALTH_EVERY * 2)

    def start_due():
        conn = db.connect(settings.db_path)
        try:
            return reclaim.pass_due(settings, conn)
        finally:
            conn.close()
    while True:
        try:
            started = await loop.run_in_executor(None, start_due)
            if started:
                log.info('reclaim jobs %s', started)
        except Exception:
            log.exception('reclaiming stale DHCP names failed')
        await asyncio.sleep(600)


async def ipam_sweeps(settings):
    """Every 10 minutes: start the network sweeps that are due (each runs as its own job)."""
    from . import db
    from .ipam import sweep
    loop = asyncio.get_running_loop()
    await asyncio.sleep(HEALTH_EVERY)

    def start_due():
        conn = db.connect(settings.db_path)
        try:
            return [sweep.start(settings, conn, n) for n in sweep.due(conn)]
        finally:
            conn.close()
    while True:
        try:
            started = await loop.run_in_executor(None, start_due)
            if started:
                log.info('ipam sweep jobs %s', started)
        except Exception:
            log.exception('IPAM sweeps failed')
        await asyncio.sleep(600)
