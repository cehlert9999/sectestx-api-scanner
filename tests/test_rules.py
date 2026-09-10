"""Regelkatalog: Ground Truth, Falschmeldungsprobe, Negativtest je Regel, Blindstellen."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oas_audit import audit, check_ids, load_spec, score
from oas_audit.findings import Confidence, Finding, Severity
from oas_audit.rules import LAUFZEIT_LUECKEN

FIXTURES = Path(__file__).parent / "fixtures"
ERWARTUNG = json.loads((FIXTURES / "gp-service-demo.erwartung.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------- Ground Truth


@pytest.fixture(scope="module")
def demo():
    return audit(load_spec(str(FIXTURES / ERWARTUNG["spec"])))


def _nennt(f: Finding, subject: str) -> bool:
    """Bezieht sich der Befund auf diese Operation bzw. diesen Pfad?"""
    kandidaten = [f.subject, *f.affected, *(e.pointer for e in f.evidence)]
    if f.method:
        kandidaten.append(f"{f.method} {f.subject}")
    pfad = subject.split(" ", 1)[-1]
    ptr = pfad.replace("~", "~0").replace("/", "~1")
    return any(subject == k or pfad == k or ptr in k for k in kandidaten)


@pytest.mark.parametrize("bug", [b for b in ERWARTUNG["bugs"] if b["static"] == "certain"],
                         ids=lambda b: b["id"])
def test_sicher_erkennbare_bugs_werden_belegt(bug, demo):
    treffer = [f for f in demo.findings
               if f.check_id == bug["check"] and _nennt(f, bug["subject"])]
    assert treffer, f"{bug['id']}: {bug['check']} nennt {bug['subject']} nicht"
    assert any(f.confidence is Confidence.BELEGT for f in treffer), \
        f"{bug['id']}: nur als Hinweis gefunden, muss belegt sein"


@pytest.mark.parametrize("bug", [b for b in ERWARTUNG["bugs"] if b["static"] == "candidate"],
                         ids=lambda b: b["id"])
def test_kandidaten_werden_als_pruefauftrag_genannt(bug, demo):
    treffer = [f for f in demo.findings
               if f.check_id == bug["check"] and _nennt(f, bug["subject"])]
    assert treffer, f"{bug['id']}: {bug['check']} nennt {bug['subject']} nicht"


@pytest.mark.parametrize("bug", [b for b in ERWARTUNG["bugs"] if b["static"] == "impossible"],
                         ids=lambda b: b["id"])
def test_laufzeitbugs_stehen_unter_den_luecken(bug, demo):
    """Was statisch nicht entscheidbar ist, wird benannt — nie behauptet."""
    assert bug["gap"] in {g.key for g in demo.runtime_gaps}, f"{bug['id']}: Lücke {bug['gap']} fehlt"


def test_abdeckungsquote_ist_die_gemessene(demo):
    """12 von 22 — die Zahl steht gleichrangig neben der Note im Bericht."""
    statisch = [b for b in ERWARTUNG["bugs"] if b["static"] != "impossible"]
    assert len(ERWARTUNG["bugs"]) == 22
    assert len(statisch) == 12


def test_demo_note_und_deckel(demo):
    sc = score(demo)
    assert sc.design.letter == "F"
    assert any(c.check_id == "endpoint.unauth_sensitive_response" and c.cap == "F" for c in sc.design.caps)
    assert sc.hygiene.letter in ("A", "B"), "Hygiene darf das Design nicht wegmitteln — und umgekehrt"


def test_demo_meldet_keine_beispielwerte(demo):
    """Nur Feldnamen im Bericht — nie Werte aus example/default."""
    text = json.dumps(demo.model_dump(mode="json"), ensure_ascii=False)
    for wert in ("DE89370400440532013000", "Max Mustermann", "secret123"):
        assert wert not in text


def test_demo_rauschgrenze(demo):
    """Nicht mehr Einzelbefunde als Operationen — sonst liest den Bericht niemand."""
    einzeln = [f for f in demo.findings if f.aggregate_count is None]
    assert len(einzeln) <= demo.endpoint_count


# ------------------------------------------------------ Falschmeldungsprobe


def test_saubere_spec_bekommt_note_a():
    r = audit(load_spec(str(FIXTURES / "clean-api.yaml")))
    belegt = [f for f in r.findings if f.confidence is Confidence.BELEGT]
    assert not belegt, "Falschmeldung: " + ", ".join(f"{f.check_id} {f.subject}" for f in belegt)
    laut = [f for f in r.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert not laut, "Zu laut: " + ", ".join(f.check_id for f in laut)
    sc = score(r)
    assert (sc.design.letter, sc.hygiene.letter) == ("A", "A")
    assert not r.blind_spots


# ------------------------------------------------------------ Blindstellen


def test_oas32_konstrukte_werden_als_blindstellen_ausgewiesen():
    r = audit(load_spec(str(FIXTURES / "oas32-constructs.yaml")))
    was = " | ".join(b.what for b in r.blind_spots)
    assert "QUERY" in was
    assert "PURGE" in was
    assert "querystring" in was
    assert "itemSchema" in was
    assert "Webhooks" in was
    assert "OpenAPI 3.2.0" in was
    # und nichts davon wurde stillschweigend als geprüft gemeldet
    assert r.endpoint_count == 2


def test_zyklisches_schema_bricht_nicht():
    spec = _spec({"/nodes/{nodeId}": {"get": _op(responses=_json({"$ref": "#/components/schemas/Node"}))}},
                 schemes=_BEARER, security=[{"Bearer": []}],
                 components={"schemas": {"Node": {"type": "object", "properties": {
                     "id": {"type": "string"},
                     "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}},
                 }}}})
    import jsonref
    r = audit(jsonref.replace_refs(spec, lazy_load=False))
    assert r.endpoint_count == 1


# ------------------------------------------------- Negativtest je Regel


_BEARER = {"Bearer": {"type": "http", "scheme": "bearer"}}
_OK = {"200": {"description": "ok"}}


def _spec(paths: dict, *, schemes=None, security=None, servers=None, version="3.0.3",
          components=None, swagger=None) -> dict[str, Any]:
    if swagger:
        d: dict[str, Any] = {"swagger": "2.0", "info": {"title": "t", "version": "1"}, "paths": paths}
        d.update(swagger)
        if schemes:
            d["securityDefinitions"] = schemes
        if security is not None:
            d["security"] = security
        return d
    d = {"openapi": version, "info": {"title": "t", "version": "1"}, "paths": paths}
    if servers:
        d["servers"] = [{"url": u} for u in servers]
    comp: dict[str, Any] = {}
    if schemes:
        comp["securitySchemes"] = schemes
    if components:
        comp.update(components)
    if comp:
        d["components"] = comp
    if security is not None:
        d["security"] = security
    return d


def _op(**kw) -> dict[str, Any]:
    kw.setdefault("responses", _OK)
    return kw


def _json(schema, code="200") -> dict[str, Any]:
    return {code: {"description": "ok", "content": {"application/json": {"schema": schema}}}}


def _obj(**props) -> dict[str, Any]:
    return {"type": "object", "properties": {k: ({"type": v} if isinstance(v, str) else v)
                                             for k, v in props.items()}}


def _ids(spec) -> set[str]:
    return {f.check_id for f in audit(spec).findings}


_SEC = dict(schemes=_BEARER, security=[{"Bearer": []}])
_ID = {"name": "thingId", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
_INT_ID = {"name": "thingId", "in": "path", "required": True, "schema": {"type": "integer"}}

FAELLE: list[tuple[str, dict, dict]] = [
    ("spec.no_security_schemes",
     _spec({"/a": {"get": _op()}}),
     _spec({"/a": {"get": _op()}}, **_SEC)),
    ("spec.no_global_security",
     _spec({"/a": {"get": _op(security=[{"Bearer": []}])}}, schemes=_BEARER),
     _spec({"/a": {"get": _op()}}, **_SEC)),
    ("spec.security_or_semantics",
     _spec({"/a": {"get": _op(security=[{"Bearer": []}, {"Key": []}])}},
           schemes={**_BEARER, "Key": {"type": "apiKey", "in": "header", "name": "X-Key"}}),
     _spec({"/a": {"get": _op(security=[{"Bearer": [], "Key": []}])}},
           schemes={**_BEARER, "Key": {"type": "apiKey", "in": "header", "name": "X-Key"}})),
    ("spec.api_key_in_query",
     _spec({"/a": {"get": _op()}}, schemes={"Key": {"type": "apiKey", "in": "query", "name": "key"}}, security=[{"Key": []}]),
     _spec({"/a": {"get": _op()}}, schemes={"Key": {"type": "apiKey", "in": "header", "name": "X-Key"}}, security=[{"Key": []}])),
    ("spec.basic_auth",
     _spec({"/a": {"get": _op()}}, schemes={"B": {"type": "http", "scheme": "basic"}}, security=[{"B": []}]),
     _spec({"/a": {"get": _op()}}, **_SEC)),
    ("spec.oauth2_implicit",
     _spec({"/a": {"get": _op()}}, security=[{"O": ["r"]}],
           schemes={"O": {"type": "oauth2", "flows": {"implicit": {"authorizationUrl": "https://x/a", "scopes": {"r": "r"}}}}}),
     _spec({"/a": {"get": _op()}}, security=[{"O": ["r"]}],
           schemes={"O": {"type": "oauth2", "flows": {"authorizationCode": {"authorizationUrl": "https://x/a", "tokenUrl": "https://x/t", "scopes": {"r": "r"}}}}})),
    ("spec.oauth2_no_scopes",
     _spec({"/a": {"get": _op()}}, security=[{"O": []}],
           schemes={"O": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "https://x/t", "scopes": {}}}}}),
     _spec({"/a": {"get": _op()}}, security=[{"O": ["r"]}],
           schemes={"O": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "https://x/t", "scopes": {"r": "r"}}}}})),
    ("spec.http_server",
     _spec({"/a": {"get": _op()}}, servers=["http://api.acme-corp.de"], **_SEC),
     _spec({"/a": {"get": _op()}}, servers=["https://api.acme-corp.de"], **_SEC)),
    ("spec.nonprod_server",
     _spec({"/a": {"get": _op()}}, servers=["http://localhost:8000", "https://staging.acme-corp.de"], **_SEC),
     _spec({"/a": {"get": _op()}}, servers=["https://api.acme-corp.de"], **_SEC)),
    ("spec.version_sprawl",
     _spec({"/v1/a": {"get": _op()}, "/v2/a": {"get": _op()}}, **_SEC),
     _spec({"/v1/a": {"get": _op()}, "/v1/b": {"get": _op()}}, **_SEC)),
    ("spec.deprecated_no_sunset",
     _spec({"/a": {"get": _op(deprecated=True)}}, **_SEC),
     _spec({"/a": {"get": _op(deprecated=True, description="Sunset 2027-01-01, ersetzt durch /b")}}, **_SEC)),
    ("gateway.wm_detected",
     _spec({"/a": {"get": _op()}}, schemes={"GW": {"type": "apiKey", "in": "header", "name": "x-Gateway-APIKey"}}, security=[{"GW": []}]),
     _spec({"/a": {"get": _op()}}, **_SEC)),
    ("endpoint.unauth_write",
     _spec({"/things": {"post": _op(security=[])}}, **_SEC),
     _spec({"/things": {"post": _op()}, "/auth/login": {"post": _op(security=[])}}, **_SEC)),
    ("endpoint.unauth_id_read",
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID], security=[])}}, **_SEC),
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID])}}, **_SEC)),
    ("endpoint.unauth_sensitive_response",
     _spec({"/things": {"get": _op(security=[], responses=_json(_obj(iban="string")))}}, **_SEC),
     _spec({"/things": {"get": _op(responses=_json(_obj(iban="string")))},
            "/auth/login": {"post": _op(security=[], responses=_json(_obj(access_token="string")))}}, **_SEC)),
    ("endpoint.admin_path",
     _spec({"/admin/users": {"get": _op()}, "/internal/flush": {"post": _op(security=[])}}, **_SEC),
     _spec({"/users": {"get": _op()}}, **_SEC)),
    ("endpoint.debug_path",
     _spec({"/actuator/env": {"get": _op(security=[])}, "/debug/vars": {"get": _op()}}, **_SEC),
     _spec({"/health": {"get": _op(security=[])}}, **_SEC)),
    ("endpoint.credentials_in_query",
     _spec({"/a": {"get": _op(parameters=[{"name": "api_key", "in": "query", "schema": {"type": "string"}}])}}, **_SEC),
     _spec({"/a": {"get": _op(parameters=[{"name": "q", "in": "query", "schema": {"type": "string"}}])}}, **_SEC)),
    ("schema.credential_in_response",
     _spec({"/users/{thingId}": {"get": _op(parameters=[_ID], responses=_json(_obj(password_hash="string")))}}, **_SEC),
     _spec({"/users/{thingId}": {"get": _op(parameters=[_ID], responses=_json(_obj(name="string")))},
            "/auth/token": {"post": _op(security=[], responses=_json(_obj(access_token="string")))}}, **_SEC)),
    ("schema.sensitive_in_response",
     _spec({"/things": {"get": _op(responses=_json(_obj(iban="string")))}}, **_SEC),
     _spec({"/things": {"get": _op(responses=_json(_obj(name="string")))}}, **_SEC)),
    ("endpoint.object_level_access",
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID])}}, **_SEC),
     _spec({"/things": {"get": _op()}}, **_SEC)),
    ("endpoint.sequential_integer_id",
     _spec({"/things/{thingId}": {"get": _op(parameters=[_INT_ID])}}, **_SEC),
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID])}}, **_SEC)),
    ("endpoint.list_without_pagination",
     _spec({"/things": {"get": _op(responses=_json({"type": "array", "items": _obj(id="string")}))}}, **_SEC),
     _spec({"/things": {"get": _op(parameters=[{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                                   responses=_json({"type": "array", "items": _obj(id="string")}))}}, **_SEC)),
    ("endpoint.unbounded_upload",
     _spec({"/files": {"post": _op(requestBody={"content": {"multipart/form-data": {"schema": _obj(file={"type": "string", "format": "binary"})}}})}}, **_SEC),
     _spec({"/files": {"post": _op(requestBody={"content": {"multipart/form-data": {"schema": _obj(file={"type": "string", "format": "binary", "maxLength": 10485760})}}})}}, **_SEC)),
    ("endpoint.no_error_responses",
     _spec({"/a": {"get": _op()}}, **_SEC),
     _spec({"/a": {"get": _op(responses={**_OK, "401": {"description": "nein"}})}}, **_SEC)),
    ("endpoint.write_without_scope",
     _spec({"/things": {"post": _op()}}, **_SEC),
     _spec({"/things": {"post": _op()}}, security=[{"O": ["things:write"]}],
           schemes={"O": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "https://x/t", "scopes": {"things:write": "w"}}}}})),
    ("schema.additional_properties_open",
     _spec({"/things": {"post": _op(requestBody={"content": {"application/json": {"schema": _obj(name={"type": "string", "maxLength": 10})}}})}}, **_SEC),
     _spec({"/things": {"post": _op(requestBody={"content": {"application/json": {"schema": {**_obj(name={"type": "string", "maxLength": 10}), "additionalProperties": False}}}})}}, **_SEC)),
    ("schema.no_constraints",
     _spec({"/things": {"post": _op(requestBody={"content": {"application/json": {"schema": {**_obj(name="string"), "additionalProperties": False}}}})}}, **_SEC),
     _spec({"/things": {"post": _op(requestBody={"content": {"application/json": {"schema": {**_obj(name={"type": "string", "maxLength": 10}), "additionalProperties": False}}}})}}, **_SEC)),
    ("path.crud_method_gap",
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID])}}, **_SEC),
     _spec({"/things/{thingId}": {"get": _op(parameters=[_ID]), "delete": _op(parameters=[_ID])}}, **_SEC)),
]


@pytest.mark.parametrize("check_id,positiv,negativ", FAELLE, ids=[f[0] for f in FAELLE])
def test_regel_greift_und_schweigt(check_id, positiv, negativ):
    assert check_id in _ids(positiv), f"{check_id} greift nicht, wo es soll"
    assert check_id not in _ids(negativ), f"{check_id} meldet, wo nichts ist"


def test_jede_regel_hat_einen_negativtest():
    """Ohne Negativtest keine Aufnahme in den Katalog."""
    getestet = {f[0] for f in FAELLE}
    fehlend = set(check_ids()) - getestet
    assert not fehlend, "Regeln ohne Negativtest: " + ", ".join(sorted(fehlend))
    unbekannt = getestet - set(check_ids())
    assert not unbekannt, "Tests für nicht existierende Regeln: " + ", ".join(sorted(unbekannt))


def test_swagger2_wird_gleich_behandelt():
    spec = _spec({"/things/{thingId}": {"get": _op(parameters=[{"name": "thingId", "in": "path", "required": True, "type": "integer"}])},
                  "/upload": {"post": _op(parameters=[{"name": "f", "in": "formData", "type": "file"}])}},
                 swagger={"host": "api.acme-corp.de", "schemes": ["http", "https"]},
                 schemes={"B": {"type": "basic"}}, security=[{"B": []}])
    ids = _ids(spec)
    assert {"spec.http_server", "spec.basic_auth", "endpoint.sequential_integer_id",
            "endpoint.unbounded_upload"} <= ids


def test_findings_sind_stabil_und_haben_fundstellen():
    a = audit(load_spec(str(FIXTURES / "gp-service-demo.json")))
    b = audit(load_spec(str(FIXTURES / "gp-service-demo.json")))
    assert [f.id for f in a.findings] == [f.id for f in b.findings]
    for f in a.findings:
        if f.aggregate_count is None:
            assert f.evidence and f.evidence[0].pointer.startswith("#/"), f.check_id


def test_hinweise_bewerten_nie():
    r = audit(load_spec(str(FIXTURES / "gp-service-demo.json")))
    for f in r.findings:
        assert f.scores == (f.confidence is Confidence.BELEGT)


def test_laufzeitluecken_decken_alle_owasp_klassen_der_regeln_ab():
    assert len(LAUFZEIT_LUECKEN) >= 10
    assert len({g.key for g in LAUFZEIT_LUECKEN}) == len(LAUFZEIT_LUECKEN)
