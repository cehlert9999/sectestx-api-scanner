"""Die Zusage „nichts wird gespeichert, nichts wird gelesen“ — gemessen, nicht behauptet.

Drei Nachweise:
1. Ein echter Scan in einem frischen Verzeichnis (cwd, TMPDIR, HOME) hinterlässt keine Datei.
2. Der Arbeitsprozess *kann* keine Datei schreiben, auch wenn er wollte (RLIMIT_FSIZE 0).
3. Kein Log-Eintrag des Dienstes enthält Inhalt aus dem Dokument — bei Erfolg, bei Fehlern, bei Abbruch.
"""

from __future__ import annotations

import json
import logging
import multiprocessing as mp
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oas_audit.service.app import create_app
from oas_audit.service.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"
MARKER = "GEHEIMNIS-7f3a9c-NICHT-SPEICHERN"


def _spec_mit_marker() -> str:
    text = (FIXTURES / "clean-api.yaml").read_text(encoding="utf-8")
    # Der Marker steht an drei typischen Stellen: Titel, Beschreibung, Beispielwert.
    text = text.replace("title: Clean Orders API", f"title: {MARKER}-Titel")
    text = text.replace("summary: Bestellungen auflisten", f"summary: {MARKER}-Beschreibung")
    text = text.replace("id: {type: string, format: uuid}", f"id: {{type: string, format: uuid, example: {MARKER}-Wert}}")
    return text


@pytest.fixture
def client():
    return TestClient(create_app(Settings(secret="t", scans_per_hour=100, scans_per_day=100)))


def test_scan_hinterlaesst_keine_datei(tmp_path, monkeypatch, client):
    """cwd, TMPDIR und HOME zeigen auf ein leeres Verzeichnis — es muss leer bleiben."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    r = client.post("/api/v1/scan", json={"spec": _spec_mit_marker()})
    assert r.status_code == 200
    # auch ein fehlerhaftes Dokument darf nichts hinterlassen
    client.post("/api/v1/scan", json={"spec": "{ kaputt: [" + MARKER})
    dateien = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert not dateien, "Dateien nach dem Scan: " + ", ".join(str(p) for p in dateien)


def test_arbeitsprozess_kann_nicht_schreiben(tmp_path):
    """RLIMIT_FSIZE 0: der Schreibversuch scheitert, die Datei bleibt leer oder fehlt."""
    ziel = tmp_path / "leak.txt"
    ctx = mp.get_context("spawn")
    p = ctx.Process(target=_helper_target, args=(str(ziel),))
    p.start()
    p.join(20)
    assert not p.is_alive()
    assert p.exitcode != 0, "Der Arbeitsprozess konnte trotz Limit eine Datei schreiben"
    assert not ziel.exists() or ziel.stat().st_size == 0


def _helper_target(ziel: str) -> None:  # pragma: no cover — läuft im Kindprozess
    from tests._sandbox_helper import versuche_zu_schreiben

    versuche_zu_schreiben(ziel)


def test_logs_enthalten_keinen_dokumentinhalt(caplog, client):
    caplog.set_level(logging.DEBUG)
    faelle = [
        _spec_mit_marker(),                                    # gültig
        "openapi: 3.0.0\ninfo: {title: " + MARKER + "}\n",     # ohne paths → trotzdem gültig
        "{ kaputt: [" + MARKER,                                # Parse-Fehler
        "- " + MARKER,                                         # kein Objekt
        "openapi: 3.0.0\ninfo: {title: x, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {$ref: '#/components/schemas/" + MARKER + "'}\n",  # Referenz-Fehler
    ]
    for spec in faelle:
        client.post("/api/v1/scan", json={"spec": spec})
    assert MARKER not in caplog.text
    assert "Titel" not in caplog.text and "Beschreibung" not in caplog.text


def test_antwort_enthaelt_keine_beispielwerte(client):
    """Feldnamen ja, Werte nie — auch nicht der Titel-Marker in Fundstellen-Auszügen."""
    r = client.post("/api/v1/scan", json={"spec": _spec_mit_marker()})
    body = r.json()
    assert f"{MARKER}-Wert" not in r.text
    # Der Titel des Dokuments wird bewusst zurückgegeben (er ist die Überschrift des Berichts),
    # aber nur im dafür vorgesehenen Feld — nirgends sonst.
    assert body["source"]["title"] == f"{MARKER}-Titel"
    ohne_titel = dict(body)
    ohne_titel["source"] = dict(body["source"], title="")
    assert MARKER not in json.dumps(ohne_titel, ensure_ascii=False)


def test_kein_access_log_im_start():
    """Der Startbefehl schaltet das Access-Log ab — keine IPs, keine Pfade auf Platte."""
    quelle = (Path(__file__).parents[1] / "src/oas_audit/service/__main__.py").read_text(encoding="utf-8")
    assert "access_log=False" in quelle


def test_umgebung_hat_keine_spec_auf_platte_nach_dem_lauf(tmp_path, monkeypatch, client):
    """Auch das Betriebssystem-Temp (falls TMPDIR ignoriert wird) zeigt keine neue Datei mit Marker."""
    import tempfile
    vorher = {p for p in Path(tempfile.gettempdir()).glob("*") if p.is_file()}
    client.post("/api/v1/scan", json={"spec": _spec_mit_marker()})
    neu = [p for p in Path(tempfile.gettempdir()).glob("*") if p.is_file() and p not in vorher]
    verdaechtig = []
    for p in neu:
        try:
            if MARKER in p.read_text(errors="ignore"):
                verdaechtig.append(str(p))
        except OSError:
            pass
    assert not verdaechtig, "Dokumentinhalt im Temp-Verzeichnis: " + ", ".join(verdaechtig)
