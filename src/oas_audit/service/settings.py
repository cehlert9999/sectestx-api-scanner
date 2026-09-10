"""Konfiguration über Umgebungsvariablen — mit sicheren Voreinstellungen."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    #: Erlaubte Browser-Ursprünge. Leer = kein CORS (nur same-origin).
    allowed_origins: list[str] = field(default_factory=lambda: [
        o.strip() for o in os.environ.get("OAS_AUDIT_ALLOWED_ORIGINS", "").split(",") if o.strip()
    ])
    #: Geheimnis für Ergebnis-Signaturen und IP-Hashes. Ohne Angabe pro
    #: Prozessstart zufällig — Signaturen gelten dann nur bis zum Neustart.
    secret: str = field(default_factory=lambda: os.environ.get("OAS_AUDIT_SECRET") or secrets.token_hex(32))
    #: Vertraut X-Forwarded-For (nur hinter dem eigenen Reverse-Proxy setzen).
    trust_proxy: bool = field(default_factory=lambda: os.environ.get("OAS_AUDIT_TRUST_PROXY", "0") == "1")

    max_upload_bytes: int = field(default_factory=lambda: _int("OAS_AUDIT_MAX_UPLOAD", 2 * 1024 * 1024))
    scans_per_hour: int = field(default_factory=lambda: _int("OAS_AUDIT_SCANS_PER_HOUR", 5))
    scans_per_day: int = field(default_factory=lambda: _int("OAS_AUDIT_SCANS_PER_DAY", 20))
    global_scans_per_day: int = field(default_factory=lambda: _int("OAS_AUDIT_GLOBAL_PER_DAY", 500))
    parallel_scans: int = field(default_factory=lambda: _int("OAS_AUDIT_PARALLEL", 4))

    #: Grenzen des Arbeitsprozesses.
    worker_memory_bytes: int = field(default_factory=lambda: _int("OAS_AUDIT_WORKER_MEM", 512 * 1024 * 1024))
    worker_cpu_seconds: int = field(default_factory=lambda: _int("OAS_AUDIT_WORKER_CPU", 5))
    worker_wall_seconds: float = field(default_factory=lambda: float(_int("OAS_AUDIT_WORKER_WALL", 8)))
