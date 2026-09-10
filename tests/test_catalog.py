"""Der Prüfsatz: deterministisch, ohne Payloads, an der Ground Truth messbar."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from oas_audit import audit, load_spec
from oas_audit.catalog import to_markdown
from oas_audit.findings import Confidence

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def demo():
    return audit(load_spec(str(FIXTURES / "gp-service-demo.json")))


@pytest.fixture(scope="module")
def clean():
    return audit(load_spec(str(FIXTURES / "clean-api.yaml")))


def _find(result, key, path=None, method=None):
    """Trifft je Operation oder je Pfad (method=None mit Methodenliste in also_applies_to)."""
    out = []
    for c in result.catalog:
        if c.key != key:
            continue
        if path is not None and not (c.path == path or any(a.endswith(" " + path) or a == path for a in c.also_applies_to)):
            continue
        if method is not None and c.method != method and f"{method} {path}" not in c.also_applies_to:
            continue
        out.append(c)
    return out


@pytest.mark.parametrize("key,path,method", [
    ("bola.cross_user", "/api/v1/partners/{partner_id}", "GET"),
    ("bola.cross_user", "/api/v1/contracts/{contract_id}", "GET"),
    ("bola.cross_user", "/api/v1/partners/by-number/{partner_number}", "GET"),
    ("bfla.admin_as_user", "/api/v1/admin/stats", None),
    ("bfla.admin_as_user", "/api/v1/admin/export/partners", None),
    ("bfla.write_least_privilege", "/api/v1/tariffs", "POST"),
    ("bopla.mass_assignment", "/api/v1/partners", "POST"),
    ("confirm.unauthenticated", "/api/v0/partners", "GET"),
    ("confirm.unauthenticated", "/debug/health", "GET"),
    ("confirm.unauthenticated", "/actuator/env", "GET"),
    ("auth.alternatives", "/gateway/api/v1/partners", "GET"),
    ("gateway.key_without_user", None, None),
    ("gateway.trust_header", None, None),
    ("auth.jwt_unsigned", None, None),
    ("api9.old_versions", None, None),
    ("api8.cors", None, None),
], ids=lambda x: str(x))
def test_demo_prüfsatz_deckt_die_ground_truth(demo, key, path, method):
    assert _find(demo, key, path, method), f"{key} für {method} {path} fehlt"


def test_belegte_befunde_werden_als_bestaetigung_markiert(demo):
    c = _find(demo, "confirm.unauthenticated", "/api/v0/partners", "GET")[0]
    assert c.static_state is Confidence.BELEGT
    assert c.priority == 1
    assert c.related_check == "endpoint.unauth_sensitive_response"


def test_hinweise_werden_als_wahrscheinlich_markiert(demo):
    c = _find(demo, "bola.cross_user", "/api/v1/partners/{partner_id}", "GET")[0]
    assert c.static_state is Confidence.WAHRSCHEINLICH
    assert c.priority == 1, "sensible Felder im Response → zuerst prüfen"
    assert "GET /api/v1/partners/{partner_id}" in c.also_applies_to and "DELETE /api/v1/partners/{partner_id}" in c.also_applies_to


def test_saubere_spec_bekommt_trotzdem_einen_pruefsatz(clean):
    keys = {c.key for c in clean.catalog}
    assert {"auth.enforced", "bola.cross_user", "bopla.mass_assignment", "api8.cors", "api4.rate_limit"} <= keys
    assert not any(c.static_state is Confidence.BELEGT for c in clean.catalog)


def test_keine_ausfuehrbaren_payloads(demo):
    """Der Katalog beschreibt Verhalten — er enthält keine Angriffsstrings."""
    verboten = re.compile(r"' OR |<script|\.\./|%00|UNION SELECT|alg[\"']?\s*:\s*[\"']none[\"']|eyJ[A-Za-z0-9_-]{10,}", re.I)
    text = json.dumps([c.model_dump(mode="json") for c in demo.catalog], ensure_ascii=False)
    assert not verboten.search(text)


def test_katalog_ist_deterministisch(demo):
    zweitlauf = audit(load_spec(str(FIXTURES / "gp-service-demo.json")))
    assert [c.id for c in demo.catalog] == [c.id for c in zweitlauf.catalog]
    assert len({c.id for c in demo.catalog}) == len(demo.catalog), "IDs müssen eindeutig sein"


def test_katalog_ist_nach_prioritaet_sortiert(demo):
    prios = [c.priority for c in demo.catalog]
    assert prios == sorted(prios)
    assert demo.catalog[0].priority == 1


def test_umfang_bleibt_lesbar(demo):
    """Mehr als zwei Testfälle je Operation plus ein Dutzend API-weite wäre kein Prüfsatz, sondern eine Liste."""
    assert 40 <= len(demo.catalog) <= 2 * demo.endpoint_count + 12
    from collections import Counter
    assert Counter(c.key for c in demo.catalog)["bopla.response_fields"] <= 5, "je Schema, nicht je Operation"


def test_englisch(demo):
    en = audit(load_spec(str(FIXTURES / "gp-service-demo.json")), lang="en")
    assert len(en.catalog) == len(demo.catalog)
    assert [c.id for c in en.catalog] == [c.id for c in demo.catalog], "Sprache ändert keine IDs"
    assert any("Request another user" in c.title for c in en.catalog)
    assert not any("Fremdes Objekt" in c.title for c in en.catalog)


def test_jeder_fall_traegt_controls_und_alle_felder(demo):
    for c in demo.catalog:
        assert c.controls and any(x.startswith("OWASP") for x in c.controls)
        assert "ISO/IEC 27001:2022 8.29" in c.controls
        assert c.precondition and c.steps and c.expected and c.fail_signal


def test_markdown_export(demo):
    md = to_markdown(demo.catalog, "de", title=demo.title)
    assert md.startswith("# Prüfsatz: GP-Service Demo-API")
    assert md.count("## [P") == len(demo.catalog)
    assert "**Erwartet:**" in md
