"""Rauch-Tests: das ausgekoppelte Paket muss ohne sectestx vollständig arbeiten."""

from __future__ import annotations

from pathlib import Path

from oas_audit import OpenAPIParser, classify_all, load_spec
from oas_audit.models import HttpMethod, OperationType

FIXTURE = Path(__file__).parent / "petstore.yaml"


def test_keine_abhaengigkeit_zurueck_ins_pro_produkt():
    """Kein Modul des freien Pakets darf ``sectestx`` importieren.

    Die Grenze ist die Geschäftsgrundlage: statisch = offen, verifiziert = Pro.
    Menschen vergessen solche Grenzen beim schnellen Fix, ein Test nicht.
    Deshalb AST-basiert statt über Pfadnamen — das Repo-Verzeichnis heißt
    selbst "sectestx" und würde jede Pfad-Heuristik zum Fehlalarm machen.
    """
    import ast

    paket = Path(__import__("oas_audit").__file__).parent
    verstoesse = []
    for datei in sorted(paket.rglob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"), filename=str(datei))
        for knoten in ast.walk(baum):
            if isinstance(knoten, ast.Import):
                namen = [a.name for a in knoten.names]
            elif isinstance(knoten, ast.ImportFrom):
                namen = [knoten.module or ""]
            else:
                continue
            for name in namen:
                if name == "sectestx" or name.startswith("sectestx."):
                    verstoesse.append(f"{datei.name}:{knoten.lineno} -> {name}")

    assert not verstoesse, "Import aus dem Pro-Produkt: " + "; ".join(verstoesse)


def test_petstore_wird_geparst_und_klassifiziert():
    spec = load_spec(str(FIXTURE))
    endpoints = OpenAPIParser(spec).parse()
    assert endpoints, "Petstore liefert keine Endpoints"

    classified = classify_all(endpoints)
    assert len(classified) == len(endpoints)
    assert all(c.operation_type in OperationType for c in classified)


def test_klassifikator_erkennt_id_ressourcen():
    spec = load_spec(str(FIXTURE))
    classified = classify_all(OpenAPIParser(spec).parse())
    id_reads = [c for c in classified if c.is_id_keyed_read]
    assert id_reads, "Petstore hat GET /pets/{petId} — muss als ID-Read erkannt werden"
    for c in id_reads:
        assert c.endpoint.method == HttpMethod.GET
        assert c.id_like_parameter is not None


def test_documented_methods_pro_pfad():
    spec = load_spec(str(FIXTURE))
    classified = classify_all(OpenAPIParser(spec).parse())
    nach_pfad: dict[str, set[HttpMethod]] = {}
    for c in classified:
        nach_pfad.setdefault(c.endpoint.path, set()).add(c.endpoint.method)
    for c in classified:
        assert set(c.documented_methods) == nach_pfad[c.endpoint.path]


def test_unbekannte_spec_version_wird_abgelehnt():
    import pytest

    with pytest.raises(ValueError):
        OpenAPIParser({"info": {"title": "t"}, "paths": {}})
