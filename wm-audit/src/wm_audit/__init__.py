"""wm-audit — statische Security-Analyse für webMethods-API-Gateway-Exporte.

Eine OpenAPI-Spezifikation beschreibt, was eine Schnittstelle tun soll. Ein
Gateway-Export beschreibt, was sie tatsächlich tut: welche Policies greifen,
welches Backend angesprochen wird, welche Protokolle erlaubt sind. Befunde aus
dieser Quelle sind deshalb Feststellungen und keine Vermutungen — ohne dass
dafür eine einzige Anfrage an die Schnittstelle nötig wäre.

Was auch die Konfiguration nicht beantwortet, steht in
:data:`~wm_audit.rules.LAUFZEIT_LUECKEN` und wird im Bericht benannt und
gezählt, aber nie bewertet.
"""

from oas_audit.findings import Confidence, Evidence, Finding, RuntimeGap, Scope

from wm_audit.bericht import VERSION, als_html, als_json, als_text, bericht
from wm_audit.models import (
    GatewayApi,
    GatewayExport,
    NativeEndpoint,
    PolicyAction,
    Uebersprungen,
)
from wm_audit.reader import (
    GESPERRTE_ASSETS,
    ExportFehler,
    Grenzen,
    read_directory,
    read_export,
    read_zip,
)
from wm_audit.rules import LAUFZEIT_LUECKEN, run_rules

__version__ = VERSION

__all__ = [
    "GESPERRTE_ASSETS",
    "LAUFZEIT_LUECKEN",
    "Confidence",
    "Evidence",
    "ExportFehler",
    "Finding",
    "GatewayApi",
    "GatewayExport",
    "Grenzen",
    "NativeEndpoint",
    "PolicyAction",
    "RuntimeGap",
    "Scope",
    "Uebersprungen",
    "als_html",
    "als_json",
    "als_text",
    "bericht",
    "read_directory",
    "read_export",
    "read_zip",
    "run_rules",
]
