"""Tests für die ODER/UND-Semantik von ``security``.

Der Unterschied ist sicherheitsrelevant und war im ursprünglichen Parser nicht
abbildbar: ``security: [{A}, {B}]`` heißt „A *oder* B genügt", während
``security: [{A, B}]`` beide verlangt. Hinter einem API-Gateway ist die erste
Variante fast immer ein Fehler.
"""

from __future__ import annotations

from oas_audit.parser.openapi import OpenAPIParser

SCHEMES = {
    "ApiKey": {"type": "apiKey", "in": "header", "name": "x-Gateway-APIKey"},
    "ApiKeyQuery": {"type": "apiKey", "in": "query", "name": "apikey"},
    "Bearer": {"type": "http", "scheme": "bearer"},
    "Basic": {"type": "http", "scheme": "basic"},
}


def _spec(security, *, global_security=None):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "components": {"securitySchemes": SCHEMES},
        "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    if security is not None:
        spec["paths"]["/x"]["get"]["security"] = security
    if global_security is not None:
        spec["security"] = global_security
    return spec


def _parse_one(security, **kw):
    return OpenAPIParser(_spec(security, **kw)).parse()[0]


def test_oder_verknuepfung_wird_als_zwei_gruppen_erkannt():
    ep = _parse_one([{"ApiKey": []}, {"Bearer": []}])
    assert len(ep.security_alternatives) == 2
    assert [len(g) for g in ep.security_alternatives] == [1, 1]
    assert ep.has_alternative_auth is True


def test_und_verknuepfung_bleibt_eine_gruppe():
    ep = _parse_one([{"ApiKey": [], "Bearer": []}])
    assert len(ep.security_alternatives) == 1
    assert len(ep.security_alternatives[0]) == 2
    assert ep.has_alternative_auth is False


def test_flache_liste_bleibt_rueckwaertskompatibel():
    """``security`` muss weiter alle Requirements flach enthalten."""
    ep = _parse_one([{"ApiKey": []}, {"Bearer": []}])
    assert len(ep.security) == 2
    assert {s.type for s in ep.security} == {"apiKey", "http"}
    assert ep.requires_auth is True


def test_apikey_location_wird_uebernommen():
    ep = _parse_one([{"ApiKeyQuery": []}])
    assert ep.security[0].location == "query"
    assert ep.security[0].name == "apikey"


def test_header_apikey_hat_location_header():
    ep = _parse_one([{"ApiKey": []}])
    assert ep.security[0].location == "header"


def test_ohne_security_keine_alternativen():
    ep = _parse_one(None)
    assert ep.security_alternatives == []
    assert ep.security == []
    assert ep.requires_auth is False
    assert ep.has_alternative_auth is False


def test_globales_security_greift_wenn_operation_keines_hat():
    ep = _parse_one(None, global_security=[{"Bearer": []}])
    assert ep.requires_auth is True
    assert len(ep.security_alternatives) == 1


def test_operation_security_ueberschreibt_global():
    ep = _parse_one([{"ApiKey": []}], global_security=[{"Bearer": []}])
    assert [s.type for s in ep.security] == ["apiKey"]


def test_leeres_operation_security_hebt_globales_auf():
    """``security: []`` an der Operation macht sie bewusst öffentlich."""
    ep = _parse_one([], global_security=[{"Bearer": []}])
    assert ep.requires_auth is False


def test_unbekanntes_scheme_wird_ignoriert_und_erzeugt_keine_leere_gruppe():
    ep = _parse_one([{"GibtsNicht": []}])
    assert ep.security_alternatives == []
    assert ep.security == []


def test_gemischt_gueltig_und_unbekannt_behaelt_nur_gueltige():
    ep = _parse_one([{"ApiKey": [], "GibtsNicht": []}])
    assert len(ep.security_alternatives) == 1
    assert [s.type for s in ep.security_alternatives[0]] == ["apiKey"]


def test_swagger2_security_definitions():
    spec = {
        "swagger": "2.0",
        "info": {"title": "t", "version": "1"},
        "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}},
        "paths": {"/x": {"get": {"security": [{"key": []}], "responses": {"200": {}}}}},
    }
    ep = OpenAPIParser(spec).parse()[0]
    assert ep.security[0].location == "header"
    assert ep.security[0].name == "X-Key"
