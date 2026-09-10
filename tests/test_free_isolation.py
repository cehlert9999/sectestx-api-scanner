"""Der freie Dienst bleibt frei — maschinell abgesichert.

Menschen vergessen solche Grenzen beim schnellen Fix, ein Test nicht.
"""

from __future__ import annotations

import ast
from pathlib import Path

import oas_audit

PAKET = Path(oas_audit.__file__).parent
SERVICE = PAKET / "service"

VERBOTENE_MODULE = ("sectestx", "subprocess", "os.system", "requests", "urllib.request", "socket")
#: Das Pro-Produkt in einem Wort: alles, was Requests baut oder ausführt.
VERBOTENE_PRAEFIXE = ("sectestx.", "sectestx")


def _imports(datei: Path):
    baum = ast.parse(datei.read_text(encoding="utf-8"), filename=str(datei))
    for k in ast.walk(baum):
        if isinstance(k, ast.Import):
            for a in k.names:
                yield k.lineno, a.name
        elif isinstance(k, ast.ImportFrom):
            yield k.lineno, k.module or ""


def test_service_importiert_nichts_verbotenes():
    verstoesse = []
    for datei in sorted(SERVICE.rglob("*.py")):
        for zeile, name in _imports(datei):
            if name in VERBOTENE_MODULE or name.startswith(VERBOTENE_PRAEFIXE):
                verstoesse.append(f"{datei.name}:{zeile} -> {name}")
    assert not verstoesse, "; ".join(verstoesse)


def test_service_nutzt_keinen_dateipfad_loader():
    """``load_spec`` kennt einen Datei-Fallback — mit Nutzereingaben ein LFI-Vektor."""
    treffer = []
    for datei in sorted(SERVICE.rglob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        for k in ast.walk(baum):
            if isinstance(k, ast.Name) and k.id == "load_spec":
                treffer.append(f"{datei.name}:{k.lineno}")
            if isinstance(k, ast.ImportFrom) and k.module and "parser" in k.module:
                for a in k.names:
                    if a.name == "load_spec":
                        treffer.append(f"{datei.name}:{k.lineno} (import)")
    assert not treffer, "load_spec im Dienst: " + ", ".join(treffer)


def test_service_holt_nichts_aus_dem_netz():
    """Kein httpx, kein urllib: URL-Fetch ist der einzige SSRF-Vektor und bleibt draußen."""
    for datei in sorted(SERVICE.rglob("*.py")):
        for zeile, name in _imports(datei):
            assert not name.startswith(("httpx", "urllib", "aiohttp", "requests")), \
                f"{datei.name}:{zeile} -> {name}"


def test_service_schreibt_keine_dateien():
    """``open(...)`` mit Schreibmodus oder Path.write_* hat im Dienst nichts verloren."""
    treffer = []
    for datei in sorted(SERVICE.rglob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        for k in ast.walk(baum):
            if isinstance(k, ast.Call):
                fn = k.func
                if isinstance(fn, ast.Name) and fn.id == "open":
                    treffer.append(f"{datei.name}:{k.lineno} open()")
                if isinstance(fn, ast.Attribute) and fn.attr in ("write_text", "write_bytes", "mkdir", "touch"):
                    treffer.append(f"{datei.name}:{k.lineno} {fn.attr}")
    assert not treffer, ", ".join(treffer)
