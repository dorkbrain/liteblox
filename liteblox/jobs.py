"""Background jobs (node bootstrap, ...): one thread per job, log kept in SQLite for the UI to poll."""

import logging
import threading
from datetime import datetime

from . import db

log = logging.getLogger(__name__)


class JobLog:
    """Callable that appends timestamped lines to a job's log."""

    def __init__(self, db_path, job_id, echo=None):
        self.db_path = db_path
        self.job_id = job_id
        self.echo = echo

    def __call__(self, line=''):
        stamped = f"{datetime.now().strftime('%H:%M:%S')}  {line}\n"
        conn = db.connect(self.db_path)
        try:
            with conn:
                conn.execute('UPDATE jobs SET log = log || ? WHERE id = ?', (stamped, self.job_id))
        finally:
            conn.close()
        if self.echo:
            self.echo(line)


def _finish(db_path, job_id, status):
    conn = db.connect(db_path)
    try:
        with conn:
            conn.execute("UPDATE jobs SET status = ?, finished_at = datetime('now') WHERE id = ?",
                         (status, job_id))
    finally:
        conn.close()


def _run(db_path, job_id, func, joblog):
    try:
        if func.__code__.co_argcount >= 2:
            func(joblog, job_id)
        else:
            func(joblog)
        joblog('✓ Done')
        _finish(db_path, job_id, 'ok')
    except Exception as e:
        log.exception('job %s failed', job_id)
        joblog(f'ERROR: {e}')
        _finish(db_path, job_id, 'failed')


def start(db_path, kind, func, node_id=None, username=None, background=True, echo=None, zone_id=None):
    """Run func(joblog) as a job; returns the job id. background=False runs it inline (CLI, tests).

    func may take a second argument, the job id, if it needs to link records to the job.
    """
    conn = db.connect(db_path)
    try:
        with conn:
            job_id = conn.execute('INSERT INTO jobs (kind, node_id, zone_id, username) VALUES (?, ?, ?, ?)',
                                  (kind, node_id, zone_id, username)).lastrowid
    finally:
        conn.close()
    joblog = JobLog(db_path, job_id, echo)
    if background:
        threading.Thread(target=_run, args=(db_path, job_id, func, joblog), daemon=True,
                         name=f'job-{job_id}').start()
    else:
        _run(db_path, job_id, func, joblog)
    return job_id


def get(conn, job_id):
    return conn.execute('SELECT * FROM jobs WHERE id = ?', (job_id,)).fetchone()


def fail_interrupted(db_path):
    """Jobs still 'running' at startup died with the previous process."""
    conn = db.connect(db_path)
    try:
        with conn:
            conn.execute("UPDATE jobs SET status = 'failed', finished_at = datetime('now'), "
                         "log = log || 'ERROR: interrupted by a restart\n' WHERE status = 'running'")
    finally:
        conn.close()
