"""Bericht eines Laufs — als JSON (maschinenlesbar) und als Text.

Das JSON-Format ``wm-audit-bericht/1`` ist der Vertrag mit der Rust-Portierung:
beide Implementierungen liefern für denselben Export byte-identische Ausgaben
(Schlüssel sortiert, zwei Leerzeichen Einzug, UTF-8 ohne ASCII-Escapes). Die
Golden-Files unter ``tests/golden`` prüfen genau das.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oas_audit.findings import Finding
from oas_audit.models import Severity

from wm_audit.models import GatewayExport
from wm_audit.rules import LAUFZEIT_LUECKEN, run_rules

VERSION = "0.2.0"
WERKZEUG = f"wm-audit {VERSION}"
FORMAT = "wm-audit-bericht/1"

#: Rangfolge der Schwere, 0 = am schwersten.
RANG = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4}


def _quellname(source: str) -> str:
    """Nur der letzte Pfadteil — vollständige Pfade verraten Benutzer- und Ablagenamen."""
    return Path(source).resolve().name


def _befund(f: Finding) -> dict[str, Any]:
    d = f.model_dump(mode="json")
    d["id"] = f.id
    d["bewertet"] = f.scores
    return d


def bericht(export: GatewayExport, befunde: list[Finding] | None = None) -> dict[str, Any]:
    befunde = run_rules(export) if befunde is None else befunde
    schwere = {s.value: 0 for s in Severity}
    for f in befunde:
        schwere[f.severity.value] += 1
    return {
        "format": FORMAT,
        "werkzeug": WERKZEUG,
        "quelle": {
            "name": _quellname(export.source),
            "art": export.art,
            "sha256": export.sha256,
        },
        "zusammenfassung": {
            "apis_gelesen": len(export.apis),
            "apis_eindeutig": len({a.label for a in export.apis}),
            "befunde": len(befunde),
            "belegt": sum(1 for f in befunde if f.scores),
            "schwere": schwere,
            "uebersprungen": len(export.uebersprungen),
            "gesperrt": export.gesperrt,
        },
        "apis": [
            {
                "label": a.label,
                "name": a.name,
                "version": a.version,
                "id": a.id,
                "pfad": a.source_path,
                "policies": [x.template_key for x in a.policy_actions],
            }
            for a in export.apis
        ],
        "befunde": [_befund(f) for f in befunde],
        "laufzeit_luecken": [g.model_dump(mode="json") for g in LAUFZEIT_LUECKEN],
        "uebersprungen": [u.model_dump() for u in export.uebersprungen],
    }


def als_json(b: dict[str, Any]) -> str:
    return json.dumps(b, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


#: Gemeinsame Vorlage mit der Rust-Fassung (code/wm-audit-rs/src/bericht.html,
#: ein Test prüft die Gleichheit). Lädt nichts nach (Content-Security-Policy).
_VORLAGE = Path(__file__).with_name("bericht.html")
_PLATZHALTER = "__WM_AUDIT_BERICHT__"


def als_html(b: dict[str, Any]) -> str:
    """Selbsttragender HTML-Bericht: die Vorlage plus das JSON als Datenblock.

    Jedes ``<`` im JSON wird als ``\\u003c`` geschrieben — Werte aus dem Export
    können den ``<script>``-Block so nicht verlassen. Die Vorlage setzt alle
    Werte nur als Text ein, nie als HTML.
    """
    daten = als_json(b).replace("<", "\\u003c")
    return _VORLAGE.read_text(encoding="utf-8").replace(_PLATZHALTER, daten, 1)


def als_text(b: dict[str, Any]) -> str:
    z = b["zusammenfassung"]
    q = b["quelle"]
    zeilen = [f"{b['werkzeug']} · {q['name']} ({q['art']})"]
    if q["sha256"]:
        zeilen.append(f"SHA-256: {q['sha256']}")
    zeilen.append(
        f"{z['apis_gelesen']} APIs gelesen ({z['apis_eindeutig']} eindeutig) · "
        f"{z['uebersprungen']} Dateien übersprungen · "
        f"{z['gesperrt']} gesperrte Einträge nicht geöffnet"
    )
    zeilen.append("")
    zeilen.append(f"Befunde: {z['befunde']} ({z['belegt']} belegt)")
    for f in b["befunde"]:
        zeilen.append(
            f"  {f['severity'].upper():<8}  {f['confidence']:<14}  "
            f"{f['check_id']:<28}  {f['subject']}"
        )
        zeilen.append(f"            {f['title']}")
    if b["uebersprungen"]:
        zeilen.append("")
        zeilen.append("Übersprungen:")
        for u in b["uebersprungen"]:
            zeilen.append(f"  {u['grund']:<16}  {u['pfad']}")
    zeilen.append("")
    zeilen.append(f"Statisch nicht prüfbar ({len(b['laufzeit_luecken'])}):")
    for g in b["laufzeit_luecken"]:
        zeilen.append(f"  {g['owasp'] or '-':<4}  {g['title']}")
    return "\n".join(zeilen) + "\n"


def ueber_schwelle(b: dict[str, Any], schwelle: str) -> bool:
    """Gibt es einen **belegten** Befund mit mindestens dieser Schwere?"""
    grenze = RANG[Severity(schwelle)]
    return any(f["bewertet"] and RANG[Severity(f["severity"])] <= grenze for f in b["befunde"])
