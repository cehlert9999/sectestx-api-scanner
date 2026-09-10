"""oas-audit — statische OWASP-Security-Analyse für OpenAPI-Spezifikationen.

Der Kern beantwortet eine Frage: *Was steht in dieser Spezifikation, das
sicherheitsrelevant ist — und was wäre daran zu testen?*

Es wird dabei **kein einziger Request** gegen die beschriebene API gesendet.
Alles, was dieses Paket ausgibt, ist aus dem Dokument abgeleitet und damit
notwendigerweise eine Aussage über die *Spezifikation*, nicht über das
tatsächliche Verhalten der Schnittstelle.
"""

from oas_audit.audit import AuditResult, audit
from oas_audit.classifier import classify, classify_all
from oas_audit.findings import (
    BlindSpot,
    Confidence,
    Evidence,
    Finding,
    RuntimeGap,
    Scope,
    aggregate,
)
from oas_audit.models import (
    ClassifiedEndpoint,
    Endpoint,
    HttpMethod,
    OperationType,
    OWASPCategory,
    PathParameter,
    SecurityRequirement,
    Severity,
)
from oas_audit.parser import OpenAPIParser, extract_base_url, load_spec
from oas_audit.rules import LAUFZEIT_LUECKEN, AuditContext, check_ids, run_rules
from oas_audit.scoring import Grade, Score, score

__version__ = "0.2.0"

__all__ = [
    "LAUFZEIT_LUECKEN",
    "AuditContext",
    "AuditResult",
    "BlindSpot",
    "ClassifiedEndpoint",
    "Confidence",
    "Endpoint",
    "Evidence",
    "Finding",
    "Grade",
    "HttpMethod",
    "OWASPCategory",
    "OpenAPIParser",
    "OperationType",
    "PathParameter",
    "RuntimeGap",
    "Scope",
    "Score",
    "SecurityRequirement",
    "Severity",
    "aggregate",
    "audit",
    "check_ids",
    "classify",
    "classify_all",
    "extract_base_url",
    "load_spec",
    "run_rules",
    "score",
]
