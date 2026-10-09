"""Regeln gegen konstruierte Fixtures mit bekannter Erwartung.

Der Satz ist bewusst klein und vollständig kontrolliert: jede API enthält genau
die eingebauten Fehler aus ``erwartung.json``, plus eine korrekt konfigurierte
Referenz. Damit prüft jeder Test beides — dass die Regel greift, wo sie soll,
und dass sie schweigt, wo nichts ist.

``fixtures/echt/`` bildet die Struktur echter Exporte nach (Policy mit
``policyEnforcements``, Routing über Alias, Wahrheitswerte als Text).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wm_audit import als_json, bericht, read_directory, run_rules
from wm_audit.rules import _REGELN

FIXTURES = Path(__file__).parent / "fixtures"
ERWARTUNG = json.loads((FIXTURES / "erwartung.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def export():
    return read_directory(FIXTURES)


@pytest.mark.parametrize("fall", ERWARTUNG["faelle"], ids=lambda f: f["api"])
def test_erwartete_befunde(fall, export):
    """Genau die erwarteten Befunde — nicht mehr und nicht weniger."""
    gefunden = {f.check_id for f in run_rules(export)
                if f.subject == fall["api"] and not f.aggregate_count}
    erwartet = set(fall["erwartet"])
    assert gefunden == erwartet, (
        f"{fall['api']}: nicht erkannt {erwartet - gefunden}, "
        f"zusätzlich {gefunden - erwartet} ({fall['warum']})"
    )


def test_jede_regel_hat_einen_positiven_fall():
    erwartet = {c for fall in ERWARTUNG["faelle"] for c in fall["erwartet"]}
    ids = {f.check_id for f in run_rules(read_directory(FIXTURES))}
    assert len(erwartet) == len(_REGELN), "jede Regel braucht mindestens ein Fixture"
    assert erwartet <= ids


def test_saubere_api_erzeugt_keinen_befund(export):
    """Die Falschmeldungsprobe — ohne sie ist der Katalog wertlos."""
    treffer = [f for f in run_rules(export)
               if f.subject == "SauberAPI 1.0" and not f.aggregate_count]
    assert not treffer, "Falschmeldung: " + ", ".join(f.check_id for f in treffer)


def test_keine_regel_stuetzt_sich_auf_active_flag():
    """``active`` ist im Export durchgehend False und darf nichts auslösen.

    Geprüft wird der Syntaxbaum, nicht der Text: die Datei *erwähnt* das Feld in
    ihrer Dokumentation genau deshalb, weil keine Regel es lesen darf.
    """
    import ast

    quelle = (Path(__file__).parents[1] / "src/wm_audit/rules.py").read_text(encoding="utf-8")
    zugriffe = [
        f"Zeile {k.lineno}"
        for k in ast.walk(ast.parse(quelle))
        if isinstance(k, ast.Attribute) and k.attr == "active_flag"
    ]
    assert not zugriffe, "Regel liest das Artefakt-Feld active_flag: " + ", ".join(zugriffe)


def test_findings_sind_stabil(export):
    """Gleiche Eingabe, gleiche Kennungen — sonst ist kein Golden File möglich."""
    a = {f.id for f in run_rules(export)}
    b = {f.id for f in run_rules(read_directory(FIXTURES))}
    assert a == b


def test_nur_belegte_befunde_wirken_auf_die_bewertung(export):
    """Hinweise bewerten nie; ein belegtes Aggregat zählt einmal und behält seine Severity."""
    for f in run_rules(export):
        if f.confidence.value == "wahrscheinlich":
            assert not f.scores, f"{f.check_id}: Hinweis darf nicht bewerten"
            if f.aggregate_count is not None:
                assert f.severity.value == "info"
        else:
            assert f.scores


def test_reader_liest_eingebettete_spec(export):
    api = next(a for a in export.apis if a.name == "SauberAPI")
    assert api.api_definition is not None
    assert "paths" in api.api_definition


def test_geheimnisse_werden_nicht_eingelesen(export):
    """PassmanData und Truststore liegen als Kanarienvögel in den Fixtures.

    Würden sie gelesen, entstünde eine API ``GEHEIM-KANARIE-PASSMAN`` bzw. eine
    Identify-Policy mit ``allowAnonymous`` — beides darf es nicht geben.
    """
    text = als_json(bericht(export))
    assert "GEHEIM-KANARIE" not in text
    assert export.gesperrt == 2
    assert not any(a.name.startswith("GEHEIM") for a in export.apis)


def test_zugangsdaten_aus_alias_url_erscheinen_nicht(export):
    text = als_json(bericht(export))
    assert "svc-user" not in text
    assert "http://***@backend.intern:8080" in text


def test_nicht_zugeordnete_aktion_wird_ausgewiesen(export):
    assert [(u.grund, u.pfad.rsplit("/", 1)[-1]) for u in export.uebersprungen] == [
        ("nicht_zugeordnet", "PolicyAction.c2-verwaist"),
    ]
