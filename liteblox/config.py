"""App settings from <data>/config.toml, written with defaults on first start.

Only app-level settings live here. Nodes and zones are managed in the web UI
and stored in SQLite.
"""

import os
import re
import secrets
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

DEFAULT_CONFIG = """\
# LiteBlox settings. Nodes and zones are managed in the web UI, not here.

[web]
# Session cookie lifetime in hours
session_hours = 12
# Set true when served over HTTPS (e.g. behind a reverse proxy) to mark cookies Secure
secure_cookies = false

[backups]
# Daily node config backup time, HH:MM in the container's TZ; "" disables
backup_at = "03:15"
keep_daily = 14
keep_weekly = 8
"""


class WebSettings(BaseModel):
    session_hours: int = Field(12, ge=1)
    secure_cookies: bool = False


class BackupSettings(BaseModel):
    backup_at: str = '03:15'
    keep_daily: int = Field(14, ge=1)
    keep_weekly: int = Field(8, ge=0)

    @field_validator('backup_at')
    @classmethod
    def _check_time(cls, value):
        if value and not re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', value):
            raise ValueError('backup_at must be HH:MM or ""')
        return value


class Settings(BaseModel):
    data_dir: Path
    backups_dir: Path
    web: WebSettings = Field(default_factory=WebSettings)
    backups: BackupSettings = Field(default_factory=BackupSettings)

    @property
    def config_file(self):
        return self.data_dir / 'config.toml'

    @property
    def db_path(self):
        return self.data_dir / 'liteblox.db'

    @property
    def secret_file(self):
        return self.data_dir / 'secret.key'

    @property
    def pki_dir(self):
        return self.data_dir / 'pki'

    @property
    def repo_dir(self):
        return self.data_dir / 'repo'


def load_settings(data_dir=None, backups_dir=None):
    data = Path(data_dir or os.environ.get('LITEBLOX_DATA', '/data'))
    backups = Path(backups_dir or os.environ.get('LITEBLOX_BACKUPS', '/backups'))
    data.mkdir(parents=True, exist_ok=True)
    backups.mkdir(parents=True, exist_ok=True)

    config_file = data / 'config.toml'
    if not config_file.exists():
        config_file.write_text(DEFAULT_CONFIG)

    raw = tomllib.loads(config_file.read_text())
    return Settings(data_dir=data, backups_dir=backups, **raw)


def load_secret(settings):
    """Session signing key, generated once into the data dir."""
    path = settings.secret_file
    if not path.exists():
        path.touch(mode=0o600)
        path.write_text(secrets.token_hex(32) + '\n')
    return path.read_text().strip()
