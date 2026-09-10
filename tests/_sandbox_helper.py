"""Ziel für einen Spawn-Prozess im Test: Limits setzen, dann versuchen zu schreiben."""

from __future__ import annotations

from pathlib import Path


def versuche_zu_schreiben(ziel: str) -> None:
    from oas_audit.service.sandbox import _limits

    _limits(memory=512 * 1024 * 1024, cpu=5)
    Path(ziel).write_text("darf nie auf Platte landen")
