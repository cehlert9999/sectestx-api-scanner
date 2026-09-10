"""Einstiegspunkt: Spezifikation hinein, Befunde, Blindstellen und Laufzeitlücken heraus."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

from oas_audit.catalog import Lang, TestCase, build_catalog
from oas_audit.classifier import classify_all
from oas_audit.findings import BlindSpot, Confidence, Finding, RuntimeGap
from oas_audit.models import ClassifiedEndpoint
from oas_audit.parser.openapi import OpenAPIParser
from oas_audit.rules import LAUFZEIT_LUECKEN, AuditContext, blindstellen, run_rules


class AuditResult(BaseModel):
    spec_version: str
    title: str = ""
    spec_hash: str = ""
    endpoint_count: int
    findings: list[Finding]
    blind_spots: list[BlindSpot] = Field(default_factory=list)
    runtime_gaps: list[RuntimeGap] = Field(default_factory=list)
    #: Der abgeleitete Prüfsatz — das eigentliche Produkt.
    catalog: list[TestCase] = Field(default_factory=list)

    @property
    def belegt(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence is Confidence.BELEGT and f.aggregate_count is None]

    @property
    def wahrscheinlich(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence is Confidence.WAHRSCHEINLICH and f.aggregate_count is None]

    @property
    def aggregate(self) -> list[Finding]:
        return [f for f in self.findings if f.aggregate_count is not None]


def audit(spec: dict[str, Any], *, login_endpoint: str | None = None, lang: Lang = "de") -> AuditResult:
    """Führt die vollständige statische Analyse eines bereits geladenen Dokuments aus."""
    parser = OpenAPIParser(spec)
    classified: list[ClassifiedEndpoint] = classify_all(parser.parse(), login_endpoint)
    ctx = AuditContext(spec=spec, endpoints=classified, is_v2=parser.is_v2)
    findings = run_rules(ctx)
    return AuditResult(
        spec_version=str(spec.get("openapi") or spec.get("swagger") or "?"),
        title=str((spec.get("info") or {}).get("title") or ""),
        spec_hash=_hash(spec),
        endpoint_count=len(classified),
        findings=findings,
        blind_spots=blindstellen(ctx),
        runtime_gaps=list(LAUFZEIT_LUECKEN),
        catalog=build_catalog(ctx, findings, lang),
    )


def _hash(spec: dict[str, Any]) -> str:
    try:
        text = json.dumps(spec, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = repr(spec)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
