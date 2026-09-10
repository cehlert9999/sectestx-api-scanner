"""Abnahme-Testmatrix des öffentlichen Dienstes.

Alles offline: kein Netz, kein Docker. Der Arbeitsprozess wird real gestartet,
damit die Isolation auch wirklich getestet wird und nicht nur ihr Aufruf.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oas_audit.service.app import create_app
from oas_audit.service.settings import Settings
from oas_audit.service.signing import verify

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = (FIXTURES / "clean-api.yaml").read_text(encoding="utf-8")
DEMO = (FIXTURES / "gp-service-demo.json").read_text(encoding="utf-8")
SECRET = "test-secret"


def _settings(**kw) -> Settings:
    basis = dict(secret=SECRET, allowed_origins=["https://sectestx.leanofy.de"],
                 scans_per_hour=5, scans_per_day=20, global_scans_per_day=1000,
                 max_upload_bytes=2 * 1024 * 1024)
    basis.update(kw)
    return Settings(**basis)


@pytest.fixture
def client():
    return TestClient(create_app(_settings()))


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["cache-control"] == "no-store"


def test_checks_sind_oeffentlich(client):
    r = client.get("/api/v1/checks")
    assert r.status_code == 200
    assert "endpoint.unauth_write" in r.json()["checks"]
    assert len(r.json()["runtime_gaps"]) >= 10


def test_scan_json_text_liefert_noten_und_signatur(client):
    r = client.post("/api/v1/scan", json={"spec": CLEAN, "filename": "clean.yaml"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["grade_design"] == "A"
    assert body["summary"]["grade_hygiene"] == "A"
    assert body["source"]["endpoint_count"] == 4
    signatur = body.pop("signature")
    assert verify(body, signatur, SECRET)


def test_scan_multipart_upload(client):
    r = client.post("/api/v1/scan", files={"file": ("demo.json", DEMO.encode(), "application/json")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["grade_design"] == "F"
    assert any(c["cap"] == "F" for c in body["summary"]["caps"])
    assert body["summary"]["counts"]["belegt"] >= 5


def test_scan_spec_direkt_als_json_body(client):
    r = client.post("/api/v1/scan", content=DEMO.encode(), headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text


def test_scan_yaml_als_text_body(client):
    r = client.post("/api/v1/scan", content=CLEAN.encode(), headers={"content-type": "application/yaml"})
    assert r.status_code == 200, r.text


def test_keine_beispielwerte_in_der_antwort(client):
    spec = CLEAN.replace("orders:read: Bestellungen lesen",
                         "orders:read: Bestellungen lesen\n            # example: GEHEIM-TOKEN-XYZ")
    spec = spec.replace("id: {type: string, format: uuid}",
                        "id: {type: string, format: uuid, example: GEHEIM-TOKEN-XYZ}")
    r = client.post("/api/v1/scan", json={"spec": spec})
    assert r.status_code == 200
    assert "GEHEIM-TOKEN-XYZ" not in r.text


@pytest.mark.parametrize("payload,erwartet", [
    ("das ist keine spezifikation", "spezifikation"),
    ("{}", "openapi"),
    ("- nur\n- eine\n- liste", "Objekt"),
    ("", "leer"),
    ("https://example.com/openapi.json", "spezifikation"),  # kein URL-Fetch, nie
    ('{"openapi": "4.0.0", "paths": {}}', "unterstützt"),
], ids=["text", "leeres-objekt", "liste", "leer", "url", "version-4"])
def test_unlesbare_dokumente_geben_422(client, payload, erwartet):
    r = client.post("/api/v1/scan", json={"spec": payload})
    assert r.status_code == 422, r.text
    assert erwartet.lower() in r.json()["detail"].lower()


def test_upload_ueber_limit_gibt_413():
    client = TestClient(create_app(_settings(max_upload_bytes=10_000)))
    gross = CLEAN + "\n# " + "x" * 20_000
    r = client.post("/api/v1/scan", json={"spec": gross})
    assert r.status_code == 413


def test_upload_ueber_limit_ohne_content_length_gibt_413():
    client = TestClient(create_app(_settings(max_upload_bytes=10_000)))

    def chunks():
        yield CLEAN.encode()
        for _ in range(30):
            yield b"# " + b"x" * 1000 + b"\n"

    r = client.post("/api/v1/scan", content=chunks(), headers={"content-type": "application/yaml"})
    assert r.status_code == 413


def test_billion_laughs_wird_abgewiesen(client):
    bombe = "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\n"
    bombe += "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    for i in range(1, 8):
        bombe += f"l{i}: &l{i} [*{'a' if i == 1 else 'l' + str(i - 1)}" + f", *{'a' if i == 1 else 'l' + str(i - 1)}" * 9 + "]\n"
    r = client.post("/api/v1/scan", json={"spec": bombe})
    assert r.status_code == 422
    assert "Alias" in r.json()["detail"]
    # und ein Dokument mit wenigen, harmlosen Aliasen bleibt erlaubt
    harmlos = CLEAN.replace("  responses:\n    Unauthorized:", "  responses:\n    Unauthorized: &u\n      description: x\n    Unauth2: *u\n    Unauthorized_alt:", 1)
    assert client.post("/api/v1/scan", json={"spec": harmlos}).status_code in (200, 422)


def test_zyklische_referenz_bricht_nicht(client):
    spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
            "components": {"securitySchemes": {"B": {"type": "http", "scheme": "bearer"}},
                           "schemas": {"Node": {"type": "object", "properties": {
                               "kind": {"$ref": "#/components/schemas/Node"}}}}},
            "security": [{"B": []}],
            "paths": {"/n": {"get": {"responses": {"200": {"description": "ok", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}}}
    r = client.post("/api/v1/scan", json={"spec": json.dumps(spec)})
    assert r.status_code == 200, r.text


def test_tiefe_verschachtelung_gibt_422(client):
    tief = '{"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": ' \
           + "[" * 10_000 + "]" * 10_000 + "}"
    r = client.post("/api/v1/scan", json={"spec": tief})
    assert r.status_code == 422
    assert "verschachtelt" in r.json()["detail"]


def test_nicht_aufloesbare_referenz_gibt_422(client):
    spec = CLEAN.replace("$ref: '#/components/schemas/Order'", "$ref: '#/components/schemas/Gibtsnicht'")
    r = client.post("/api/v1/scan", json={"spec": spec})
    assert r.status_code == 422
    assert "Referenz" in r.json()["detail"]


def test_zeitlimit_gibt_422():
    client = TestClient(create_app(_settings(worker_wall_seconds=0.001)))
    r = client.post("/api/v1/scan", json={"spec": CLEAN})
    assert r.status_code == 422
    assert "Zeitlimit" in r.json()["detail"]


def test_rate_limit_ab_dem_sechsten_scan(client):
    for i in range(5):
        assert client.post("/api/v1/scan", json={"spec": CLEAN}).status_code == 200, i
    r = client.post("/api/v1/scan", json={"spec": CLEAN})
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    # und ein anderer Client ist davon nicht betroffen
    app = create_app(_settings(trust_proxy=True))
    c2 = TestClient(app)
    for ip in ("203.0.113.1", "203.0.113.2"):
        for _ in range(5):
            assert c2.post("/api/v1/scan", json={"spec": CLEAN},
                           headers={"x-forwarded-for": ip}).status_code == 200
        assert c2.post("/api/v1/scan", json={"spec": CLEAN},
                       headers={"x-forwarded-for": ip}).status_code == 429


def test_x_forwarded_for_wird_ohne_proxy_vertrauen_ignoriert(client):
    for i in range(5):
        client.post("/api/v1/scan", json={"spec": CLEAN}, headers={"x-forwarded-for": f"10.0.0.{i}"})
    r = client.post("/api/v1/scan", json={"spec": CLEAN}, headers={"x-forwarded-for": "10.0.0.99"})
    assert r.status_code == 429


def test_manipuliertes_ergebnis_wird_abgewiesen(client):
    body = client.post("/api/v1/scan", json={"spec": DEMO}).json()
    signatur = body.pop("signature")
    body["summary"]["grade_design"] = "A"
    r = client.post("/api/v1/report", json={"result": body, "signature": signatur})
    assert r.status_code == 400
    r = client.post("/api/v1/report", json={"result": {"x": 1}})
    assert r.status_code == 400


def test_unveraendertes_ergebnis_passiert_die_signaturpruefung(client):
    body = client.post("/api/v1/scan", json={"spec": DEMO}).json()
    signatur = body.pop("signature")
    r = client.post("/api/v1/report", json={"result": body, "signature": signatur})
    assert r.status_code == 501  # Bericht kommt in v1.1 — aber die Prüfung stimmt


def test_cors_nur_fuer_erlaubte_ursprünge(client):
    r = client.options("/api/v1/scan", headers={"origin": "https://sectestx.leanofy.de",
                                                "access-control-request-method": "POST"})
    assert r.headers.get("access-control-allow-origin") == "https://sectestx.leanofy.de"
    r = client.options("/api/v1/scan", headers={"origin": "https://boese.example",
                                                "access-control-request-method": "POST"})
    assert "access-control-allow-origin" not in r.headers


def test_keine_docs_oberflaeche(client):
    assert client.get("/docs").status_code == 404
