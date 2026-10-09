"""Golden-Files: der Vertrag zwischen Python-Referenz und Rust-Portierung.

* Ohne Marker: Python liefert für jeden Fall exakt die Soll-Ausgabe.
* ``rust``: das Rust-Binary liefert dieselben Bytes und Exit-Codes, und ein
  differenzieller Zufallstest vergleicht beide auf erzeugten Exporten.
* ``echt``: Lauf gegen die öffentlichen Exporte im Repository
  ``SoftwareAG/webmethods-api-gateway-devops`` (Pfad in ``WM_DEVOPS_REPO``).

Soll-Ausgaben neu schreiben: ``python tests/golden/erzeugen.py --erwartung``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from wm_audit import als_json, bericht, read_export
from wm_audit.__main__ import main

HIER = Path(__file__).parent
GOLDEN = HIER / "golden"
MANIFEST = json.loads((GOLDEN / "faelle.json").read_text(encoding="utf-8"))
RUST = Path(os.environ.get(
    "WM_AUDIT_RS", HIER.parents[1] / "wm-audit-rs" / "target" / "release" / "wm-audit"))

sys.path.insert(0, str(GOLDEN))
import zufall  # noqa: E402


def _pfad(fall: dict) -> str:
    return str((GOLDEN / fall["pfad"]).resolve())


@pytest.mark.parametrize("fall", MANIFEST, ids=lambda f: f["name"])
@pytest.mark.parametrize("endung", ["json", "txt", "html"])
def test_python_golden(fall, endung, capsysbinary):
    argumente = [*fall.get("argumente", []), *{"json": ["--json"], "html": ["--html"]}.get(endung, [])]
    code = main([_pfad(fall), *argumente])
    ausgabe = capsysbinary.readouterr().out
    assert code == fall.get("exit", 0)
    if not fall.get("nur_exit"):
        assert ausgabe == (GOLDEN / "erwartet" / f"{fall['name']}.{endung}").read_bytes()


# ---------------------------------------------------------------- Rust


rust = pytest.mark.skipif(not RUST.is_file(), reason=f"Rust-Binary fehlt: {RUST}")


def _rust(*argumente: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(RUST), *argumente], capture_output=True, check=False, timeout=60)


@pytest.mark.rust
@rust
@pytest.mark.parametrize("fall", MANIFEST, ids=lambda f: f["name"])
@pytest.mark.parametrize("endung", ["json", "txt", "html"])
def test_rust_golden(fall, endung):
    argumente = [*fall.get("argumente", []), *{"json": ["--json"], "html": ["--html"]}.get(endung, [])]
    lauf = _rust(_pfad(fall), *argumente)
    assert lauf.returncode == fall.get("exit", 0), lauf.stderr.decode()
    if not fall.get("nur_exit"):
        assert lauf.stdout == (GOLDEN / "erwartet" / f"{fall['name']}.{endung}").read_bytes()


@pytest.mark.rust
@rust
def test_rust_differenziell(tmp_path):
    """Python und Rust auf zufällig erzeugten Exporten — jeder Unterschied ist ein Fehler."""
    anzahl = int(os.environ.get("WM_DIFFERENZ_N", "300"))
    abweichungen = []
    for seed in range(anzahl):
        dateien = zufall.export(seed)
        for als_zip in (False, True):
            pfad = zufall.schreibe(tmp_path / f"export-{seed}", dateien, als_zip)
            erwartet = als_json(bericht(read_export(pfad))).encode("utf-8")
            lauf = _rust(str(pfad), "--json")
            if lauf.returncode != 0 or lauf.stdout != erwartet:
                abweichungen.append(f"seed={seed} zip={als_zip}: {lauf.stderr.decode()[:200]}")
    assert not abweichungen, "\n".join(abweichungen[:10])


# ---------------------------------------------------------------- Echte Exporte

ECHT = os.environ.get("WM_DEVOPS_REPO")
#: Stand, gegen den die Erwartung unten geprüft wurde.
ECHT_COMMIT = "e6bffec3be65301e07843442d39ed34d8db6be1a"


@pytest.mark.echt
@pytest.mark.skipif(not ECHT, reason="WM_DEVOPS_REPO nicht gesetzt")
def test_oeffentliche_softwareag_exporte():
    """Drei echte Exporte (Petstore, Inventory, EventAPI), 10.x-Format.

    Alle drei erlauben nur HTTP und haben keine Identify-Policy — das ist der
    Zustand der Beispiele, kein Fehlalarm. Petstore listet in ``nativeEndpoint``
    auch ``http://``, routet aber über einen Alias auf ``https://``: kein
    Klartext-Befund.
    """
    b = bericht(read_export(Path(ECHT) / "apis"))
    assert b["zusammenfassung"]["apis_gelesen"] == 3
    assert b["zusammenfassung"]["uebersprungen"] == 0
    ids = {f["check_id"]: f for f in b["befunde"]}
    assert set(ids) == {"gw.http_allowed", "gw.no_identify_policy",
                        "gw.no_traffic_limit", "gw.pass_security_headers"}
    assert ids["gw.http_allowed"]["aggregate_count"] == 3
    if RUST.is_file():
        assert _rust(str(Path(ECHT) / "apis"), "--json").stdout == als_json(b).encode("utf-8")
