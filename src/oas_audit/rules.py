"""Prüfregeln für eine OpenAPI-Spezifikation.

Jede Regel beantwortet eine Frage über das *Dokument*. Sie sagt, was daran
sicherheitsrelevant ist — nie, wie sich die Schnittstelle verhält. Deshalb
trägt jeder Befund einen von drei Zuständen (:class:`~oas_audit.findings.Confidence`):
belegt, wahrscheinlich, nur zur Laufzeit prüfbar.

Drei Grundsätze für den ganzen Katalog:

1. **Kein Befund ohne Fundstelle.** Jeder Befund verweist per JSON-Pointer auf die
   Stelle im Dokument, aus der er folgt.
2. **Nur Feldnamen, nie Werte.** Beispielwerte aus dem Dokument werden nicht
   zitiert — sie enthalten in freier Wildbahn zu oft echte Daten.
3. **Was fast überall zutrifft, ist ein Stil, keine Schwachstelle.** Eine Regel,
   die bei mehr als der Hälfte der Endpunkte anschlägt, wird zu einem Aggregat
   zusammengefasst; einige Regeln sind von vornherein als Aggregat angelegt.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

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
    Severity,
)
from oas_audit.parser.openapi import json_pointer
from oas_audit.sensitive import Kategorie, schemata, sensible_felder

# ------------------------------------------------------------------ Kontext


@dataclass
class AuditContext:
    """Alles, was eine Regel über das Dokument wissen darf."""

    spec: dict[str, Any]
    endpoints: list[ClassifiedEndpoint]
    is_v2: bool

    @property
    def security_schemes(self) -> dict[str, dict[str, Any]]:
        if self.is_v2:
            return self.spec.get("securityDefinitions") or {}
        return (self.spec.get("components") or {}).get("securitySchemes") or {}

    @property
    def schemes_pointer(self) -> str:
        return "#/securityDefinitions" if self.is_v2 else "#/components/securitySchemes"

    @property
    def global_security(self) -> list[Any]:
        return self.spec.get("security") or []

    @property
    def servers(self) -> list[tuple[str, str]]:
        """(Pointer, URL) aller Server — Swagger 2 wird auf dieselbe Form gebracht."""
        if self.is_v2:
            host = self.spec.get("host")
            if not host:
                return []
            base = self.spec.get("basePath") or ""
            return [(json_pointer("schemes", str(i)) if "schemes" in self.spec else "#/host",
                     f"{s}://{host}{base}")
                    for i, s in enumerate(self.spec.get("schemes") or ["https"])]
        out = []
        for i, srv in enumerate(self.spec.get("servers") or []):
            if isinstance(srv, dict) and srv.get("url"):
                url = str(srv["url"])
                for name, var in (srv.get("variables") or {}).items():
                    if isinstance(var, dict):
                        url = url.replace(f"{{{name}}}", str(var.get("default", "")))
                out.append((json_pointer("servers", str(i), "url"), url))
        return out


DokumentRegel = Callable[[AuditContext], Iterable[Finding]]
EndpunktRegel = Callable[[AuditContext, ClassifiedEndpoint], Iterable[Finding]]

_DOKUMENT_REGELN: list[DokumentRegel] = []
_ENDPUNKT_REGELN: list[EndpunktRegel] = []

#: Regeln, die als Stil-Beobachtung angelegt sind und immer als Aggregat erscheinen.
IMMER_AGGREGAT: frozenset[str] = frozenset({
    "schema.no_constraints",
    "schema.additional_properties_open",
    "endpoint.no_error_responses",
    "endpoint.write_without_scope",
})


def dokument_regel(fn: DokumentRegel) -> DokumentRegel:
    _DOKUMENT_REGELN.append(fn)
    return fn


def endpunkt_regel(fn: EndpunktRegel) -> EndpunktRegel:
    _ENDPUNKT_REGELN.append(fn)
    return fn


# ------------------------------------------------------------------ Helfer

_AUTH_FLOW_RE = re.compile(
    r"(^|/)(login|logout|signin|sign-in|signup|sign-up|register|registration|token|tokens|"
    r"oauth2?|auth|authenticate|authorize|refresh|password/(reset|forgot|change)|"
    r"forgot-password|reset-password|verify|verification|otp|sso|callback|session|sessions)(/|$)",
    re.IGNORECASE,
)
_ADMIN_SEGMENTE = {"admin", "administrator", "internal", "manage", "management", "root",
                   "superuser", "sudo", "backoffice", "ops"}
_DEBUG_SEGMENTE = {"debug", "actuator", "console", "metrics", "env", "heapdump", "threaddump",
                   "trace", "dump", "phpinfo", "jolokia", "prometheus", "_debug", "__debug__"}
_CREDENTIAL_QUERY_RE = re.compile(
    r"(^|_|-)(token|password|passwd|pwd|secret|api_?key|apikey|access_?token|auth|"
    r"session_?id|client_?secret|private_?key)$",
    re.IGNORECASE,
)
_PAGINATION = {"limit", "page", "offset", "cursor", "size", "per_page", "perpage", "page_size",
               "pagesize", "top", "skip", "max_results", "maxresults", "count", "after", "before",
               "page_token", "pagetoken", "next", "start"}
_NONPROD_NAMEN_RE = re.compile(r"(^|[.\-/])(localhost|staging|stage|stg|test|testing|dev|"
                               r"develop|development|qa|uat|sandbox|preprod|pre-prod|int|"
                               r"integration|demo|example\.com|example\.org)([.\-/:]|$)",
                               re.IGNORECASE)
_VERSION_RE = re.compile(r"/v(\d+)(?=/|$)", re.IGNORECASE)
_SUNSET_RE = re.compile(r"sunset|abgekündigt|abkündigung|removed (in|on|by)|end.of.life|"
                        r"retire|replaced by|ersetzt durch|use .* instead|stattdessen",
                        re.IGNORECASE)
_WRITE = {HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE}


def _segmente(path: str) -> list[str]:
    return [s.lower() for s in path.split("/") if s and not s.startswith("{")]


def _ist_auth_flow(ep: Endpoint) -> bool:
    return bool(_AUTH_FLOW_RE.search(ep.path))


def _ist_health(ep: Endpoint) -> bool:
    return _segmente(ep.path)[-1:] in (["health"], ["healthz"], ["ping"], ["ready"], ["readyz"],
                                       ["live"], ["livez"], ["version"], ["status"])


def _erfolgsschemata(ep: Endpoint) -> list[dict[str, Any]]:
    return [s for code, s in ep.response_schemas.items() if 200 <= code < 300]


def _sensibel_in_antwort(ep: Endpoint) -> dict[Kategorie, list[str]]:
    out: dict[Kategorie, list[str]] = {}
    for s in _erfolgsschemata(ep):
        for kat, felder in sensible_felder(s, auth_flow=_ist_auth_flow(ep)).items():
            liste = out.setdefault(kat, [])
            liste.extend(f for f in felder if f not in liste)
    return out


def _felder_text(felder: dict[Kategorie, list[str]], maximal: int = 6) -> str:
    alle: list[str] = []
    for kat in (Kategorie.CREDENTIAL, Kategorie.FINANZ, Kategorie.PII):
        alle.extend(f for f in felder.get(kat, []) if f not in alle)
    text = ", ".join(alle[:maximal])
    return text + (f" (+{len(alle) - maximal} weitere)" if len(alle) > maximal else "")


def _f(cep: ClassifiedEndpoint, **kw: Any) -> Finding:
    ep = cep.endpoint
    kw.setdefault("scope", Scope.ENDPUNKT)
    kw.setdefault("subject", ep.path)
    kw.setdefault("method", ep.method.value)
    kw.setdefault("evidence", [Evidence(pointer=ep.pointer)])
    return Finding(**kw)


def _d(**kw: Any) -> Finding:
    kw.setdefault("scope", Scope.DOKUMENT)
    kw.setdefault("subject", "Dokument")
    return Finding(**kw)


def _security_excerpt(ep: Endpoint) -> str:
    if not ep.security_alternatives:
        return "security: [] " + ("(an der Operation)" if ep.security_source == "operation"
                                   else "(kein globales security)")
    gruppen = [" UND ".join(r.name or r.scheme or r.type for r in g) for g in ep.security_alternatives]
    return "security: " + " ODER ".join(gruppen)


# ============================================================= Dokument-Regeln


@dokument_regel
def keine_security_schemes(ctx: AuditContext):
    """Ohne definierte Verfahren kann keine Operation Auth verlangen."""
    if ctx.security_schemes or not ctx.endpoints:
        return
    yield _d(
        check_id="spec.no_security_schemes",
        title="Kein Authentifizierungsverfahren definiert",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API2,
        cap="D",
        reason=(
            "Das Dokument definiert kein einziges Security-Scheme. Damit kann keine "
            "Operation eine Authentifizierung verlangen — entweder ist die Schnittstelle "
            "vollständig öffentlich, oder ihre Absicherung ist nicht dokumentiert."
        ),
        remediation=(
            "Die tatsächlich verwendeten Verfahren unter securitySchemes beschreiben und "
            "über ein globales security-Requirement als Standard setzen."
        ),
        evidence=[Evidence(pointer=ctx.schemes_pointer, excerpt="nicht vorhanden")],
    )


@dokument_regel
def kein_globales_security(ctx: AuditContext):
    """Ohne Root-Default ist jede neue Operation zunächst offen."""
    if not ctx.security_schemes or ctx.global_security:
        return
    offen = [c for c in ctx.endpoints if not c.endpoint.requires_auth]
    yield _d(
        check_id="spec.no_global_security",
        title="Kein globales security-Requirement",
        confidence=Confidence.BELEGT,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API2,
        dimension="hygiene",
        reason=(
            "Security-Schemes sind definiert, aber nicht als Standard für das ganze "
            "Dokument gesetzt. Jede Operation muss ihre Absicherung einzeln deklarieren — "
            f"aktuell tun das {len(ctx.endpoints) - len(offen)} von {len(ctx.endpoints)} "
            "nicht, und jede vergessene Operation ist standardmäßig offen."
        ),
        remediation=(
            "Ein globales security-Requirement setzen und bewusst öffentliche Operationen "
            "mit security: [] explizit freigeben."
        ),
        evidence=[Evidence(pointer="#/security", excerpt="nicht vorhanden")],
    )


@dokument_regel
def globale_oder_verknuepfung(ctx: AuditContext):
    """Mehrere alternative Verfahren im globalen Default — das schwächste zählt."""
    if len(ctx.global_security) < 2:
        return
    beispiel = next((c.endpoint for c in ctx.endpoints if c.endpoint.security_source == "global"), None)
    if beispiel is None or not beispiel.has_alternative_auth:
        return
    yield _d(
        check_id="spec.security_or_semantics",
        title="Globales security-Requirement akzeptiert alternative Verfahren (ODER)",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API2,
        reason=_oder_grund(beispiel),
        remediation=_ODER_ABHILFE,
        evidence=[Evidence(pointer="#/security", excerpt=_security_excerpt(beispiel))],
    )


def _oder_grund(ep: Endpoint) -> str:
    namen = [" + ".join(r.name or r.scheme or r.type for r in g) for g in ep.security_alternatives]
    return (
        f"Die Liste enthält {len(namen)} Einträge ({' | '.join(namen)}). In OpenAPI ist "
        "eine Liste mehrerer Requirement-Objekte ein ODER: jedes einzelne genügt. Es "
        "reicht also das schwächste der Verfahren — hinter einem API-Gateway ist das "
        "häufig ein API-Key, wo API-Key und Token zusammen gemeint waren."
    )


_ODER_ABHILFE = (
    "Sind beide Nachweise nötig, gehören sie in *ein* Requirement-Objekt "
    "(security: [{A: [], B: []}]). Ist die Alternative beabsichtigt, muss jedes "
    "Verfahren für sich als ausreichend gelten und entsprechend geprüft werden."
)


@dokument_regel
def security_scheme_eigenschaften(ctx: AuditContext):
    """API-Key in der URL, Basic Auth, OAuth2-Implicit, OAuth2 ohne Scopes."""
    for name, scheme in ctx.security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        ptr = json_pointer(*ctx.schemes_pointer.lstrip("#/").split("/"), name)
        typ = str(scheme.get("type", "")).lower()

        if typ == "apikey" and str(scheme.get("in", "")).lower() == "query":
            yield _d(
                check_id="spec.api_key_in_query",
                title="API-Key wird als Query-Parameter übertragen",
                confidence=Confidence.BELEGT,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
                subject=name,
                reason=(
                    f"Das Scheme „{name}“ erwartet den Schlüssel im Query-Parameter "
                    f"„{scheme.get('name', '?')}“. Query-Strings landen in Server-Logs, "
                    "Proxy-Logs, Browser-Verläufen und Referer-Headern."
                ),
                remediation="Den Schlüssel als Header (oder Cookie) übertragen.",
                evidence=[Evidence(pointer=ptr, excerpt=f"type: apiKey, in: query, name: {scheme.get('name', '')}")],
            )

        if typ in ("http", "basic") and (typ == "basic" or str(scheme.get("scheme", "")).lower() == "basic"):
            yield _d(
                check_id="spec.basic_auth",
                title="HTTP Basic Authentication",
                confidence=Confidence.BELEGT,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API2,
                subject=name,
                reason=(
                    f"Das Scheme „{name}“ verwendet Basic Auth: Benutzername und Passwort "
                    "reisen bei jeder Anfrage mit, nur Base64-kodiert. Ohne TLS sind sie "
                    "mitlesbar, mit TLS bleiben sie in jedem Log-Eintrag des Clients."
                ),
                remediation="Auf Token-basierte Verfahren (Bearer/OAuth2) umstellen.",
                evidence=[Evidence(pointer=ptr, excerpt="scheme: basic")],
            )

        if typ == "oauth2":
            flows = scheme.get("flows") if not ctx.is_v2 else {scheme.get("flow", ""): scheme}
            flows = flows or {}
            if "implicit" in flows:
                yield _d(
                    check_id="spec.oauth2_implicit",
                    title="OAuth2 Implicit Flow",
                    confidence=Confidence.BELEGT,
                    severity=Severity.MEDIUM,
                    owasp=OWASPCategory.API2,
                    subject=name,
                    reason=(
                        "Der Implicit Flow liefert das Access-Token im URL-Fragment aus. "
                        "Er ist in OAuth 2.1 gestrichen und von der IETF (BCP 212) "
                        "abgeraten, weil das Token in Verläufen und Referern landet."
                    ),
                    remediation="Authorization Code Flow mit PKCE verwenden.",
                    evidence=[Evidence(pointer=ptr + ("/flows/implicit" if not ctx.is_v2 else "/flow"),
                                       excerpt="implicit")],
                )
            alle_scopes: dict[str, Any] = {}
            for flow in flows.values():
                if isinstance(flow, dict):
                    alle_scopes.update(flow.get("scopes") or {})
            if flows and not alle_scopes:
                yield _d(
                    check_id="spec.oauth2_no_scopes",
                    title="OAuth2 ohne Scopes",
                    confidence=Confidence.BELEGT,
                    severity=Severity.LOW,
                    owasp=OWASPCategory.API5,
                    subject=name,
                    reason=(
                        f"Das Scheme „{name}“ definiert keine Scopes. Jedes Token ist damit "
                        "gleich mächtig — eine funktionsbezogene Berechtigung lässt sich "
                        "weder vergeben noch dokumentieren."
                    ),
                    remediation="Scopes je Funktionsbereich definieren und an den Operationen verlangen.",
                    evidence=[Evidence(pointer=ptr, excerpt="scopes: {}")],
                )


@dokument_regel
def server_eigenschaften(ctx: AuditContext):
    """Klartext-Transport und Nicht-Produktivziele im Dokument."""
    for ptr, url in ctx.servers:
        parsed = urlparse(url if "://" in url else "//" + url)
        host = (parsed.hostname or "").lower()
        ist_lokal = host in ("localhost", "0.0.0.0", "::1") or host.startswith("127.")
        ist_privat = False
        with contextlib.suppress(ValueError):
            ist_privat = ipaddress.ip_address(host).is_private

        if parsed.scheme == "http" and not ist_lokal:
            yield _d(
                check_id="spec.http_server",
                title="Server-URL ohne TLS",
                confidence=Confidence.BELEGT,
                severity=Severity.HIGH,
                owasp=OWASPCategory.API8,
                subject=host or url,
                reason=(
                    f"Das Dokument nennt {parsed.scheme}://{host} als Ziel. Zugangsdaten und "
                    "Nutzdaten wären auf dem Transportweg mitlesbar."
                ),
                remediation="Nur https-URLs dokumentieren und HTTP am Server abweisen.",
                evidence=[Evidence(pointer=ptr, excerpt=f"{parsed.scheme}://{host}")],
            )

        if ist_lokal or ist_privat:
            yield _d(
                check_id="spec.nonprod_server",
                title="Server-URL zeigt auf ein lokales oder privates Ziel",
                confidence=Confidence.BELEGT,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API9,
                dimension="hygiene",
                subject=host or url,
                reason=(
                    f"„{host}“ ist keine öffentlich erreichbare Adresse. Entweder ist das "
                    "Dokument ein Entwicklungsstand, oder es verrät interne Netzstruktur."
                ),
                remediation="Vor Veröffentlichung die produktive Server-URL eintragen.",
                evidence=[Evidence(pointer=ptr, excerpt=host)],
            )
        elif _NONPROD_NAMEN_RE.search(host):
            yield _d(
                check_id="spec.nonprod_server",
                title="Server-URL deutet auf eine Nicht-Produktivumgebung",
                confidence=Confidence.WAHRSCHEINLICH,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API9,
                dimension="hygiene",
                subject=host,
                reason=(
                    f"Der Hostname „{host}“ enthält einen Umgebungs-Hinweis. Test- und "
                    "Staging-Systeme sind häufig schwächer abgesichert als Produktion — "
                    "und ihre Nennung im Dokument macht sie auffindbar."
                ),
                remediation="Prüfen, ob die Umgebung öffentlich erreichbar sein soll.",
                evidence=[Evidence(pointer=ptr, excerpt=host)],
            )


@dokument_regel
def versions_wildwuchs(ctx: AuditContext):
    """Mehrere API-Versionen nebeneinander — die alte ist meist die schwächere."""
    versionen: dict[str, list[str]] = {}
    for c in ctx.endpoints:
        m = _VERSION_RE.search(c.endpoint.path)
        if m:
            versionen.setdefault("v" + m.group(1), []).append(c.endpoint.path)
    if len(versionen) < 2:
        return
    sortiert = sorted(versionen, key=lambda v: int(v[1:]))
    zaehl = ", ".join(f"{v}: {len(versionen[v])}" for v in sortiert)
    yield _d(
        check_id="spec.version_sprawl",
        title="Mehrere API-Versionen parallel dokumentiert",
        confidence=Confidence.BELEGT,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API9,
        subject=", ".join(sortiert),
        reason=(
            f"Das Dokument enthält Pfade unter {len(sortiert)} Versionspräfixen ({zaehl}). "
            "Ältere Versionen erhalten selten dieselben Sicherheitskorrekturen wie die "
            "aktuelle und sind ein bevorzugtes Ziel."
        ),
        remediation=(
            "Alte Versionen als deprecated markieren, mit Sunset-Datum versehen und "
            "abschalten; bis dahin denselben Sicherheitsstand wie die aktuelle Version halten."
        ),
        evidence=[Evidence(pointer=json_pointer("paths", versionen[sortiert[0]][0]),
                           excerpt=f"Präfixe: {', '.join(sortiert)}")],
    )


@dokument_regel
def webmethods_erkannt(ctx: AuditContext):
    """Hinweise auf ein webMethods API Gateway — dann gilt zusätzlich der Gateway-Katalog."""
    hinweise: list[str] = []
    for name, scheme in ctx.security_schemes.items():
        if isinstance(scheme, dict) and str(scheme.get("name", "")).lower() == "x-gateway-apikey":
            hinweise.append(f"Security-Scheme „{name}“ mit Header x-Gateway-APIKey")
    for _, url in ctx.servers:
        parsed = urlparse(url if "://" in url else "//" + url)
        if parsed.port in (5555, 5556) or (parsed.path or "").startswith("/gateway/"):
            hinweise.append(f"Server-URL {url}")
    if not hinweise and any(c.endpoint.path.startswith("/gateway/") for c in ctx.endpoints):
        hinweise.append("Pfade unter /gateway/")
    if not hinweise:
        return
    yield _d(
        check_id="gateway.wm_detected",
        title="Merkmale eines webMethods API Gateway",
        confidence=Confidence.BELEGT,
        severity=Severity.INFO,
        owasp=OWASPCategory.API9,
        reason=(
            "Das Dokument trägt Merkmale einer über webMethods API Gateway publizierten "
            "Schnittstelle (" + "; ".join(hinweise) + "). Die tatsächlich wirksamen "
            "Policies stehen nicht in der Spezifikation, sondern im Gateway-Export."
        ),
        remediation=(
            "Den Gateway-Export (Assets und Policies) mit wm-audit prüfen — dort ist die "
            "Identify-and-Authorize-Konfiguration direkt ablesbar."
        ),
        evidence=[Evidence(pointer=ctx.schemes_pointer, excerpt=hinweise[0])],
    )


# ============================================================= Endpunkt-Regeln


@endpunkt_regel
def unauthentifiziert_schreibend(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.requires_auth or ep.method not in _WRITE or _ist_auth_flow(ep) or cep.is_login_endpoint:
        return
    yield _f(
        cep,
        check_id="endpoint.unauth_write",
        title="Schreibende Operation ohne Authentifizierung",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API5,
        cap="D",
        reason=(
            f"{ep.method.value} {ep.path} verändert Daten, verlangt laut Dokument aber "
            "keinerlei Authentifizierung. Jeder, der die URL kennt, kann die Operation auslösen."
        ),
        remediation=(
            "Ein security-Requirement an der Operation (oder global) setzen. Ist die "
            "Operation bewusst öffentlich, das im Dokument begründen."
        ),
        evidence=[Evidence(pointer=ep.pointer, excerpt=_security_excerpt(ep))],
    )


@endpunkt_regel
def unauthentifizierter_objektzugriff(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.requires_auth or ep.method is not HttpMethod.GET or cep.id_like_parameter is None:
        return
    if _ist_auth_flow(ep):
        return
    yield _f(
        cep,
        check_id="endpoint.unauth_id_read",
        title="Objektzugriff per ID ohne Authentifizierung",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API1,
        reason=(
            f"GET {ep.path} adressiert ein einzelnes Objekt über „{cep.id_like_parameter.name}“, "
            "verlangt aber keine Authentifizierung. Ohne Identität des Aufrufers kann es "
            "keine Objektberechtigung geben — jede gültige ID ist abrufbar."
        ),
        remediation=(
            "Authentifizierung verlangen und die Objektberechtigung im Backend prüfen. "
            "Sind die Objekte bewusst öffentlich, das im Dokument festhalten."
        ),
        evidence=[Evidence(pointer=ep.pointer, excerpt=_security_excerpt(ep))],
    )


@endpunkt_regel
def unauthentifiziert_sensibel(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.requires_auth or _ist_auth_flow(ep) or cep.is_login_endpoint:
        return
    felder = _sensibel_in_antwort(ep)
    if not felder:
        return
    yield _f(
        cep,
        check_id="endpoint.unauth_sensitive_response",
        title="Sensible Daten ohne Authentifizierung abrufbar",
        confidence=Confidence.BELEGT,
        severity=Severity.CRITICAL,
        owasp=OWASPCategory.API3,
        cap="F",
        reason=(
            f"{ep.method.value} {ep.path} verlangt keine Authentifizierung und liefert laut "
            f"Antwort-Schema die Felder {_felder_text(felder)}. Das ist eine "
            "dokumentierte Offenlegung — kein Test nötig, um sie festzustellen."
        ),
        remediation=(
            "Authentifizierung verlangen und das Antwort-Schema auf die Felder beschränken, "
            "die jeder Aufrufer sehen darf."
        ),
        evidence=[Evidence(pointer=ep.pointer + "/responses", excerpt=_felder_text(felder))],
    )


def _admin_praefix(path: str) -> tuple[str, str] | None:
    teile = path.split("/")
    for i, seg in enumerate(teile):
        if seg.lower() in _ADMIN_SEGMENTE:
            return "/".join(teile[: i + 1]) or "/", seg
    return None


@endpunkt_regel
def admin_pfad_offen(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    treffer = _admin_praefix(ep.path)
    if treffer is None or ep.requires_auth:
        return
    yield _f(
        cep,
        check_id="endpoint.admin_path",
        title="Administrative Funktion ohne Authentifizierung",
        confidence=Confidence.BELEGT,
        severity=Severity.CRITICAL,
        owasp=OWASPCategory.API5,
        cap="F",
        reason=(
            f"Der Pfad {ep.path} kennzeichnet eine administrative Funktion („{treffer[1]}“) "
            "und verlangt laut Dokument keinerlei Authentifizierung."
        ),
        remediation="Authentifizierung und Rollenprüfung für alle administrativen Pfade verlangen.",
        evidence=[Evidence(pointer=ep.pointer, excerpt=_security_excerpt(ep))],
    )


@dokument_regel
def admin_pfad_gleiche_auth(ctx: AuditContext):
    """Administrative Pfade mit derselben Authentifizierung wie der Rest — je Präfix gebündelt."""
    gruppen: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in ctx.endpoints:
        treffer = _admin_praefix(cep.endpoint.path)
        if treffer is not None and cep.endpoint.requires_auth:
            gruppen.setdefault(treffer[0], []).append(cep)
    for praefix, ceps in gruppen.items():
        ops = sorted(f"{c.endpoint.method.value} {c.endpoint.path}" for c in ceps)
        yield Finding(
            check_id="endpoint.admin_path",
            title="Administrative Funktionen mit derselben Authentifizierung wie die übrige API",
            confidence=Confidence.WAHRSCHEINLICH,
            severity=Severity.HIGH,
            owasp=OWASPCategory.API5,
            scope=Scope.ENDPUNKT,
            subject=praefix,
            affected=ops,
            reason=(
                f"Unter {praefix} sind {len(ops)} administrative Operation{'en' if len(ops) != 1 else ''} "
                "dokumentiert. Das Dokument verlangt dafür ein gültiges Token, sagt aber nichts "
                "über die nötige Rolle — ob ein gewöhnlicher Benutzer abgewiesen wird, "
                "entscheidet allein das Backend."
            ),
            remediation=(
                "Die erforderliche Rolle oder den Scope an den Operationen dokumentieren und im "
                "Backend durchsetzen; im Test jede Operation mit einem Nicht-Admin-Token aufrufen."
            ),
            evidence=[Evidence(pointer=c.endpoint.pointer, excerpt=_security_excerpt(c.endpoint))
                      for c in ceps][:8],
        )


@endpunkt_regel
def debug_pfad(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    treffer = [s for s in _segmente(ep.path) if s in _DEBUG_SEGMENTE]
    if not treffer:
        return
    if ep.requires_auth:
        yield _f(
            cep,
            check_id="endpoint.debug_path",
            title="Diagnose-Endpunkt in der öffentlichen Schnittstelle",
            confidence=Confidence.WAHRSCHEINLICH,
            severity=Severity.MEDIUM,
            owasp=OWASPCategory.API8,
            reason=(
                f"{ep.path} ist ein Diagnose- oder Betriebsendpunkt („{treffer[0]}“). Er ist "
                "authentifiziert, gehört aber nicht in die Schnittstelle für Fachanwender — "
                "solche Endpunkte liefern typischerweise Konfiguration, Umgebungsvariablen "
                "oder Speicherabbilder."
            ),
            remediation="Auf einen separaten Management-Port oder ins interne Netz verlegen.",
            evidence=[Evidence(pointer=ep.pointer, excerpt=_security_excerpt(ep))],
        )
    else:
        yield _f(
            cep,
            check_id="endpoint.debug_path",
            title="Diagnose-Endpunkt ohne Authentifizierung",
            confidence=Confidence.BELEGT,
            severity=Severity.HIGH,
            owasp=OWASPCategory.API8,
            cap="D",
            reason=(
                f"{ep.path} ist ein Diagnose- oder Betriebsendpunkt („{treffer[0]}“) und "
                "verlangt keine Authentifizierung. Solche Endpunkte liefern typischerweise "
                "Konfiguration, Umgebungsvariablen, Verbindungszeichenfolgen oder Speicherabbilder."
            ),
            remediation=(
                "Entfernen oder auf einen separaten, nur intern erreichbaren Management-Port "
                "verlegen; mindestens Authentifizierung verlangen."
            ),
            evidence=[Evidence(pointer=ep.pointer, excerpt=_security_excerpt(ep))],
        )


@endpunkt_regel
def zugangsdaten_im_query(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    treffer = [p.name for p in ep.query_parameters if _CREDENTIAL_QUERY_RE.search(p.name)]
    if not treffer:
        return
    yield _f(
        cep,
        check_id="endpoint.credentials_in_query",
        title="Zugangsdaten als Query-Parameter",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API8,
        reason=(
            f"{ep.method.value} {ep.path} nimmt {', '.join(treffer)} im Query-String entgegen. "
            "Query-Strings stehen in Server- und Proxy-Logs, im Browser-Verlauf und im "
            "Referer-Header nachfolgender Anfragen."
        ),
        remediation="Zugangsdaten ausschließlich im Header oder Body übertragen.",
        evidence=[Evidence(pointer=ep.pointer + "/parameters", excerpt=", ".join(treffer))],
    )


@endpunkt_regel
def oder_verknuepfung_an_operation(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.security_source != "operation" or not ep.has_alternative_auth:
        return
    yield _f(
        cep,
        check_id="spec.security_or_semantics",
        title="Operation akzeptiert alternative Authentifizierungsverfahren (ODER)",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API2,
        reason=_oder_grund(ep),
        remediation=_ODER_ABHILFE,
        evidence=[Evidence(pointer=ep.pointer + "/security", excerpt=_security_excerpt(ep))],
    )


@endpunkt_regel
def geheimnis_in_antwort(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    felder = _sensibel_in_antwort(ep).get(Kategorie.CREDENTIAL, [])
    if not felder:
        return
    yield _f(
        cep,
        check_id="schema.credential_in_response",
        title="Geheimnis im Antwort-Schema",
        confidence=Confidence.BELEGT,
        severity=Severity.CRITICAL,
        owasp=OWASPCategory.API3,
        cap="D",
        reason=(
            f"Das Antwort-Schema von {ep.method.value} {ep.path} enthält {', '.join(felder[:6])}. "
            "Passwörter, Schlüssel und Tokens gehören in keine Antwort — auch nicht gehasht."
        ),
        remediation="Die Felder aus dem Antwort-Modell entfernen (eigenes Read-Schema ohne Geheimnisse).",
        evidence=[Evidence(pointer=ep.pointer + "/responses", excerpt=", ".join(felder[:6]))],
    )


@dokument_regel
def sensibel_in_antwort(ctx: AuditContext):
    """Finanz- und personenbezogene Felder in authentifizierten Antworten — ein Prüfauftrag.

    Gemeldet wird je *Schema*, nicht je Operation: dieselbe Struktur steckt
    typischerweise hinter Liste, Einzelabruf, Anlage und Änderung. Ein Befund
    mit acht Verwendungen ist lesbar — acht identische Befunde sind Rauschen.
    """
    gruppen: dict[int, dict[str, Any]] = {}
    for cep in ctx.endpoints:
        ep = cep.endpoint
        if not ep.requires_auth:
            continue  # ohne Auth greift endpoint.unauth_sensitive_response
        for s in _erfolgsschemata(ep):
            felder = sensible_felder(s, auth_flow=_ist_auth_flow(ep))
            finanz, pii = felder.get(Kategorie.FINANZ, []), felder.get(Kategorie.PII, [])
            if not finanz and not pii:
                continue
            kern = getattr(s, "__subject__", s)
            g = gruppen.setdefault(id(kern), {
                "name": _schema_name(s), "felder": felder, "ops": [], "pointer": ep.pointer + "/responses",
            })
            g["ops"].append(f"{ep.method.value} {ep.path}")
    for g in gruppen.values():
        finanz, pii = g["felder"].get(Kategorie.FINANZ, []), g["felder"].get(Kategorie.PII, [])
        ops: list[str] = g["ops"]
        name = g["name"] or ops[0]
        yield Finding(
            check_id="schema.sensitive_in_response",
            title="Finanz- oder personenbezogene Daten im Antwort-Schema",
            confidence=Confidence.WAHRSCHEINLICH,
            severity=Severity.HIGH if finanz else Severity.MEDIUM,
            owasp=OWASPCategory.API3,
            scope=Scope.ENDPUNKT,
            subject=name,
            affected=sorted(ops),
            reason=(
                f"Das Antwort-Schema „{name}“ ({len(ops)} Operation{'en' if len(ops) != 1 else ''}) liefert "
                + (f"Finanzdaten ({', '.join(finanz[:4])})" if finanz else "")
                + (" und " if finanz and pii else "")
                + (f"personenbezogene Daten ({', '.join(pii[:4])})" if pii else "")
                + ". Ob jeder berechtigte Aufrufer alle diese Felder sehen darf, sagt das "
                "Dokument nicht — das ist die Kernfrage der Property-Level-Autorisierung."
            ),
            remediation=(
                "Für jede Rolle ein eigenes Antwort-Modell führen und Felder, die nicht jeder "
                "braucht, weglassen statt ausblenden."
            ),
            evidence=[Evidence(pointer=g["pointer"], excerpt=_felder_text(g["felder"]),
                               note="verwendet von: " + ", ".join(ops[:6]) + (" …" if len(ops) > 6 else ""))],
        )


def _schema_name(schema: Any) -> str:
    """Name eines Schemas: der ``$ref``-Name, sonst Array-Element, sonst ein kurzer Titel."""
    ref = getattr(schema, "__reference__", None)
    if isinstance(ref, dict) and isinstance(ref.get("$ref"), str):
        return ref["$ref"].rsplit("/", 1)[-1]
    if isinstance(schema, dict) and schema.get("type") == "array":
        inner = _schema_name(schema.get("items"))
        if inner:
            return f"{inner}[]"
    titel = schema.get("title") if isinstance(schema, dict) else None
    if isinstance(titel, str) and 0 < len(titel) <= 40 and titel not in ("Response", "Body"):
        return titel
    return ""


@dokument_regel
def objektzugriff(ctx: AuditContext):
    """Authentifizierter Zugriff auf einzelne Objekte — Objektberechtigung ist zu testen.

    Gebündelt je Ressource: „partners“ mit drei Objektpfaden ist ein Prüfauftrag,
    nicht drei. Die einzelnen Pfade stehen in ``affected``.
    """
    ressourcen: dict[str, dict[str, Any]] = {}
    for cep in ctx.endpoints:
        ep = cep.endpoint
        if not ep.requires_auth or cep.id_like_parameter is None:
            continue
        felder = _sensibel_in_antwort(ep)
        sensibel = bool(felder.get(Kategorie.FINANZ) or felder.get(Kategorie.PII)
                        or felder.get(Kategorie.CREDENTIAL))
        key = (cep.resource_hint or ep.path).lower()
        r = ressourcen.setdefault(key, {"pfade": {}, "sensibel": False, "schreibend": False, "params": set()})
        r["pfade"].setdefault(ep.path, []).append(ep.method.value)
        r["sensibel"] |= sensibel
        r["schreibend"] |= ep.method in _WRITE
        r["params"].add(f"{cep.id_like_parameter.name}: {cep.id_like_parameter.schema_type or '?'}")
    for name, r in ressourcen.items():
        pfade: dict[str, list[str]] = r["pfade"]
        yield Finding(
            check_id="endpoint.object_level_access",
            title="Objektzugriff per ID — Objektberechtigung ist nicht dokumentiert",
            confidence=Confidence.WAHRSCHEINLICH,
            severity=Severity.HIGH if r["sensibel"] else Severity.MEDIUM,
            owasp=OWASPCategory.API1,
            scope=Scope.ENDPUNKT,
            subject=name,
            affected=sorted(pfade),
            reason=(
                f"Die Ressource „{name}“ wird über {len(pfade)} Pfad{'e' if len(pfade) != 1 else ''} per ID "
                f"adressiert ({', '.join(sorted(r['params']))}). Ob ein Aufrufer nur seine eigenen "
                "Objekte erreicht, steht in keiner Spezifikation — es ist die häufigste und "
                "folgenreichste Schwachstelle in APIs und nur im Betrieb prüfbar."
                + (" Die Antworten enthalten sensible Felder." if r["sensibel"] else "")
                + (" Es gibt schreibende Operationen." if r["schreibend"] else "")
            ),
            remediation=(
                "Im Backend jede ID gegen den Besitz- oder Mandantenkontext des Aufrufers prüfen; "
                "im Test mit dem Token von Nutzer A ein Objekt von Nutzer B anfordern "
                "(erwartet: 403 oder 404)."
            ),
            evidence=[Evidence(pointer=json_pointer("paths", pfad),
                               excerpt=", ".join(methoden))
                      for pfad, methoden in sorted(pfade.items())][:8],
        )


@endpunkt_regel
def enumerierbare_id(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    p = cep.id_like_parameter
    if p is None or (p.schema_type or "").lower() not in ("integer", "int32", "int64", "number"):
        return
    yield Finding(
        check_id="endpoint.sequential_integer_id",
        title="Objekt-ID ist eine ganze Zahl",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API1,
        scope=Scope.ENDPUNKT,
        subject=ep.path,
        method=None,
        reason=(
            f"„{p.name}“ in {ep.path} ist vom Typ {p.schema_type}. Fortlaufende Zahlen lassen "
            "sich durchprobieren — eine fehlende Objektberechtigung wird damit zum "
            "vollständigen Datenabzug statt zu einem Einzelfall."
        ),
        remediation=(
            "Nicht erratbare Kennungen (UUID v4) nach außen verwenden — als Ergänzung zur "
            "Objektberechtigung, nie als Ersatz."
        ),
        evidence=[Evidence(pointer=json_pointer("paths", ep.path), excerpt=f"{{{p.name}}}: {p.schema_type}")],
    )


@endpunkt_regel
def liste_ohne_paginierung(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if cep.operation_type is not OperationType.LIST or _ist_health(ep):
        return
    if any(p.name.lower() in _PAGINATION for p in ep.query_parameters):
        return
    liefert_liste = False
    for s in _erfolgsschemata(ep):
        typ = s.get("type")
        if typ == "array" or (isinstance(typ, list) and "array" in typ):
            liefert_liste = True
        for name, sub in (s.get("properties") or {}).items():
            if isinstance(sub, dict) and sub.get("type") == "array" and \
               name.lower() in ("items", "data", "results", "records", "entries", "content", "elements", "list", "rows", "hits", "value", "values"):
                liefert_liste = True
    if not liefert_liste:
        return
    yield _f(
        cep,
        check_id="endpoint.list_without_pagination",
        title="Listenoperation ohne Paginierungsparameter",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API4,
        reason=(
            f"GET {ep.path} liefert eine Liste, kennt aber keinen Parameter zur Begrenzung "
            "(limit, page, cursor …). Jede Anfrage kann damit den gesamten Bestand abrufen — "
            "ein Lastproblem für den Server und ein Abfluss-Risiko für die Daten."
        ),
        remediation="Paginierung mit serverseitiger Obergrenze einführen und dokumentieren.",
        evidence=[Evidence(pointer=ep.pointer, excerpt="keine Paginierungsparameter")],
    )


@endpunkt_regel
def unbegrenzter_upload(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    binaer = any(ct.startswith(("multipart/", "application/octet-stream")) for ct in ep.request_content_types)
    if not binaer and ep.request_schema:
        binaer = any(s.get("format") in ("binary", "byte") for _, s in schemata(ep.request_schema))
    if not binaer:
        return
    begrenzt = False
    if ep.request_schema:
        begrenzt = any("maxLength" in s or "maxItems" in s for _, s in schemata(ep.request_schema))
    if begrenzt:
        return
    yield _f(
        cep,
        check_id="endpoint.unbounded_upload",
        title="Datei-Upload ohne dokumentierte Größenbegrenzung",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API4,
        reason=(
            f"{ep.method.value} {ep.path} nimmt Binärdaten entgegen "
            f"({', '.join(ep.request_content_types) or 'format: binary'}), ohne dass das "
            "Dokument eine Obergrenze nennt. Eine Begrenzung kann am Server existieren — "
            "belegt ist sie nicht."
        ),
        remediation="Maximale Größe und erlaubte Typen serverseitig durchsetzen und im Schema dokumentieren.",
        evidence=[Evidence(pointer=ep.pointer + "/requestBody", excerpt=", ".join(ep.request_content_types))],
    )


@endpunkt_regel
def deprecated_ohne_sunset(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if not ep.deprecated:
        return
    raw = _raw_operation(ctx, ep)
    text = " ".join(str(raw.get(k, "")) for k in ("description", "summary", "x-sunset", "x-deprecated-at", "x-removal-date"))
    if _SUNSET_RE.search(text) or "x-sunset" in raw:
        return
    yield _f(
        cep,
        check_id="spec.deprecated_no_sunset",
        title="Als veraltet markiert, aber ohne Abschaltdatum",
        confidence=Confidence.BELEGT,
        severity=Severity.LOW,
        owasp=OWASPCategory.API9,
        dimension="hygiene",
        reason=(
            f"{ep.method.value} {ep.path} ist deprecated, nennt aber weder Abschaltdatum noch "
            "Nachfolger. Veraltete Operationen bleiben so unbegrenzt erreichbar — und "
            "erhalten erfahrungsgemäß keine Sicherheitskorrekturen mehr."
        ),
        remediation="Sunset-Datum (x-sunset oder Sunset-Header) und Nachfolge-Operation dokumentieren.",
        evidence=[Evidence(pointer=ep.pointer + "/deprecated", excerpt="deprecated: true")],
    )


# ------------------------------------------ Stil-Beobachtungen (immer Aggregat)


@endpunkt_regel
def keine_fehlerantworten(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if not ep.requires_auth:
        return
    codes = {c.upper() for c in ep.response_codes}
    if codes & {"401", "403", "4XX", "DEFAULT"}:
        return
    yield _f(
        cep,
        check_id="endpoint.no_error_responses",
        title="Authentifizierte Operationen ohne dokumentierte 401/403-Antwort",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.LOW,
        owasp=OWASPCategory.API8,
        dimension="hygiene",
        reason=(
            "Die Operation verlangt Authentifizierung, dokumentiert aber nicht, was bei "
            "fehlender oder unzureichender Berechtigung passiert. Das ist meist ein "
            "Generator-Standard — es macht aber unsichtbar, ob das Verhalten je entworfen wurde."
        ),
        remediation="401 und 403 mit einem einheitlichen Fehlerschema dokumentieren.",
    )


@endpunkt_regel
def schreibend_ohne_scope(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.method not in _WRITE or not ep.requires_auth or _ist_auth_flow(ep):
        return
    raw = _raw_operation(ctx, ep)
    sec = raw.get("security") if "security" in raw else ctx.global_security
    hat_scope = any(isinstance(req, dict) and any(v for v in req.values()) for req in (sec or []))
    if hat_scope or "x-roles" in raw or "x-required-roles" in raw or "x-permissions" in raw:
        return
    yield _f(
        cep,
        check_id="endpoint.write_without_scope",
        title="Schreibende Operationen ohne dokumentierte Rolle oder Scope",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API5,
        reason=(
            "Die Operation verändert Daten und verlangt ein Token, nennt aber keine Rolle "
            "und keinen Scope. Das Dokument kann damit nicht sagen, wer schreiben darf — "
            "und im Test lässt sich nicht unterscheiden, ob ein 200 für einen "
            "gewöhnlichen Benutzer richtig oder falsch ist."
        ),
        remediation=(
            "Scopes oder Rollen je Operation dokumentieren (OAuth2-Scopes bzw. x-roles) "
            "und im Backend durchsetzen."
        ),
    )


@endpunkt_regel
def offenes_schreibschema(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if ep.method not in (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH) or not ep.request_schema:
        return
    if _ist_auth_flow(ep):
        return  # ein Login-Body ist kein Ziel für Mass Assignment
    for _, s in schemata(ep.request_schema):
        if s.get("type") == "object" or "properties" in s:
            if s.get("additionalProperties") is False:
                return
            break
    else:
        return
    yield _f(
        cep,
        check_id="schema.additional_properties_open",
        title="Schreibschemata ohne additionalProperties: false",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.LOW,
        owasp=OWASPCategory.API3,
        reason=(
            "Das Request-Schema lässt unbekannte Felder zu. Ob das Backend sie ignoriert "
            "oder übernimmt (Mass Assignment), sagt das Dokument nicht — es ist der "
            "Standard fast aller Generatoren und deshalb nur ein schwaches Signal."
        ),
        remediation=(
            "additionalProperties: false setzen, wo das Backend unbekannte Felder abweist; "
            "sonst im Backend eine Allowlist der schreibbaren Felder durchsetzen."
        ),
    )


@endpunkt_regel
def fehlende_constraints(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if not ep.request_schema:
        return
    offen: list[str] = []
    for pfad, s in schemata(ep.request_schema):
        typ = s.get("type")
        if typ == "string" and "maxLength" not in s and "enum" not in s and \
           s.get("format") not in ("uuid", "date", "date-time", "email", "binary", "byte", "ipv4", "ipv6", "uri") or typ == "array" and "maxItems" not in s:
            offen.append(pfad or "/")
    if not offen:
        return
    yield _f(
        cep,
        check_id="schema.no_constraints",
        title="Request-Schemata ohne Längenbegrenzung",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.LOW,
        owasp=OWASPCategory.API4,
        dimension="hygiene",
        reason=(
            "Strings ohne maxLength und Arrays ohne maxItems im Request-Schema. Ohne "
            "dokumentierte Grenzen lässt sich nicht prüfen, ob der Server übergroße "
            "Eingaben abweist."
        ),
        remediation="maxLength und maxItems dort setzen, wo das Backend Grenzen durchsetzt.",
    )


@endpunkt_regel
def crud_luecke(ctx: AuditContext, cep: ClassifiedEndpoint):
    ep = cep.endpoint
    if cep.id_like_parameter is None or not ep.path.rstrip("/").endswith("}"):
        return
    if ep.method is not HttpMethod.GET:
        return
    if set(cep.documented_methods) & _WRITE:
        return
    yield Finding(
        check_id="path.crud_method_gap",
        title="Objektpfad nur lesend dokumentiert",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.LOW,
        owasp=OWASPCategory.API9,
        dimension="hygiene",
        scope=Scope.ENDPUNKT,
        subject=ep.path,
        method=None,
        reason=(
            f"{ep.path} dokumentiert nur GET. Existieren PUT, PATCH oder DELETE im Backend, "
            "ohne dokumentiert zu sein, sind sie auch nicht Teil eines Reviews — und "
            "typischerweise schlechter abgesichert."
        ),
        remediation="Nicht dokumentierte Methoden abschalten (405) oder dokumentieren.",
        evidence=[Evidence(pointer=json_pointer("paths", ep.path),
                           excerpt="Methoden: " + ", ".join(m.value for m in cep.documented_methods))],
    )


def _raw_operation(ctx: AuditContext, ep: Endpoint) -> dict[str, Any]:
    item = (ctx.spec.get("paths") or {}).get(ep.path) or {}
    op = item.get(ep.method.value.lower()) if isinstance(item, dict) else None
    return op if isinstance(op, dict) else {}


# ============================================================= Laufzeitgrenze

#: Was aus einem Dokument prinzipiell nicht folgt. Wird gezählt und benannt,
#: niemals bewertet — die ehrliche Kehrseite jeder statischen Analyse.
LAUFZEIT_LUECKEN: list[RuntimeGap] = [
    RuntimeGap(key="object_authorization", title="Erreicht ein Aufrufer fremde Objekte?",
               owasp=OWASPCategory.API1,
               why="Objektberechtigung liegt im Backend und braucht zwei Identitäten."),
    RuntimeGap(key="jwt_algorithm", title="Wird ein unsigniertes Token (alg: none) abgewiesen?",
               owasp=OWASPCategory.API2,
               why="Die Spezifikation nennt „bearer“, nicht die Prüflogik dahinter."),
    RuntimeGap(key="jwt_expiry", title="Wird das Ablaufdatum eines Tokens geprüft?",
               owasp=OWASPCategory.API2,
               why="Reines Laufzeitverhalten der Token-Validierung."),
    RuntimeGap(key="api_key_verification", title="Wird ein erfundener API-Key abgewiesen?",
               owasp=OWASPCategory.API2,
               why="Ob das Gateway den Schlüssel gegen ein Register prüft, steht nicht im Dokument."),
    RuntimeGap(key="trust_header", title="Lässt sich ein Trust-Header des Gateways fälschen?",
               owasp=OWASPCategory.API2,
               why="Hängt davon ab, ob das Backend Header aus Client-Anfragen filtert."),
    RuntimeGap(key="mass_assignment", title="Übernimmt das Backend nicht dokumentierte Felder?",
               owasp=OWASPCategory.API3,
               why="Ein Schema mit additionalProperties: false ist ein Versprechen, keine Prüfung."),
    RuntimeGap(key="role_enforcement", title="Wird die Rollenprüfung durchgesetzt?",
               owasp=OWASPCategory.API5,
               why="Das Dokument nennt bestenfalls Scopes — ob sie greifen, zeigt erst ein Aufruf."),
    RuntimeGap(key="rate_limit", title="Greift ein Rate-Limit?",
               owasp=OWASPCategory.API4,
               why="Ein dokumentierter 429 belegt nicht, dass er je gesendet wird."),
    RuntimeGap(key="security_headers", title="Werden Security-Header in Antworten gesetzt?",
               owasp=OWASPCategory.API8,
               why="Antwort-Header sind nicht Teil einer OpenAPI-Beschreibung."),
    RuntimeGap(key="cors", title="Wie verhält sich CORS tatsächlich?",
               owasp=OWASPCategory.API8,
               why="Erst eine Preflight-Anfrage zeigt die wirksame Regel."),
    RuntimeGap(key="error_disclosure", title="Enthalten Fehlerantworten Stack-Traces oder Versionen?",
               owasp=OWASPCategory.API8,
               why="Fehlerformate stehen selten im Dokument und weichen im Betrieb oft davon ab."),
    RuntimeGap(key="undocumented_endpoints", title="Gibt es Endpunkte außerhalb des Dokuments?",
               owasp=OWASPCategory.API9,
               why="Was nicht dokumentiert ist, kann kein Dokument zeigen — Swagger-UI, Debug-Routen, alte Versionen."),
]


# ============================================================= Blindstellen

_BEKANNTE_PATH_ITEM_KEYS = {"$ref", "summary", "description", "servers", "parameters",
                            "get", "put", "post", "delete", "options", "head", "patch", "trace"}
_BEKANNTE_PARAM_ORTE = {"path", "query", "header", "cookie", "body", "formData"}


def blindstellen(ctx: AuditContext) -> list[BlindSpot]:
    """Strukturen, die diese Analyse nicht ausgewertet hat — namentlich, nicht pauschal."""
    out: list[BlindSpot] = []
    version = str(ctx.spec.get("openapi") or ctx.spec.get("swagger") or "")
    for path, item in (ctx.spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            out.append(BlindSpot(pointer=json_pointer("paths", path), what="Path-Item ist kein Objekt",
                                 why="Wurde übersprungen; enthält möglicherweise Operationen."))
            continue
        for key, val in item.items():
            if key in _BEKANNTE_PATH_ITEM_KEYS or key.startswith("x-"):
                continue
            if key == "additionalOperations" and isinstance(val, dict):
                for name in val:
                    out.append(BlindSpot(pointer=json_pointer("paths", path, "additionalOperations", name),
                                         what=f"Operation mit Methode „{name}“ (OpenAPI 3.2 additionalOperations)",
                                         why="Nicht-Standard-Methoden werden von keiner Regel geprüft."))
                continue
            if key == "query":
                out.append(BlindSpot(pointer=json_pointer("paths", path, "query"),
                                     what="Operation mit Methode QUERY (OpenAPI 3.2)",
                                     why="Die QUERY-Methode wird von keiner Regel geprüft."))
                continue
            out.append(BlindSpot(pointer=json_pointer("paths", path, key),
                                 what=f"Unbekannter Schlüssel „{key}“ im Path-Item",
                                 why="Wurde nicht als Operation gelesen."))
        params = list(item.get("parameters") or [])
        for verb in ("get", "put", "post", "delete", "options", "head", "patch", "trace"):
            op = item.get(verb)
            if isinstance(op, dict):
                params += list(op.get("parameters") or [])
                for code, resp in (op.get("responses") or {}).items():
                    if isinstance(resp, dict):
                        for mt, media in (resp.get("content") or {}).items():
                            if isinstance(media, dict) and "itemSchema" in media and "schema" not in media:
                                out.append(BlindSpot(
                                    pointer=json_pointer("paths", path, verb, "responses", str(code), "content", mt),
                                    what="Antwort nur mit itemSchema (OpenAPI 3.2, Streaming)",
                                    why="Antwort-Felder wurden nicht auf sensible Daten geprüft."))
                if op.get("callbacks"):
                    out.append(BlindSpot(pointer=json_pointer("paths", path, verb, "callbacks"),
                                         what="Callbacks", why="Ausgehende Aufrufe werden nicht geprüft."))
        for i, p in enumerate(params):
            if isinstance(p, dict) and p.get("in") and p["in"] not in _BEKANNTE_PARAM_ORTE:
                out.append(BlindSpot(pointer=json_pointer("paths", path, "parameters", str(i)),
                                     what=f"Parameter „{p.get('name', '?')}“ mit in: {p['in']}",
                                     why="Unbekannter Parameter-Ort (z.B. querystring, OpenAPI 3.2) — nicht ausgewertet."))
    if ctx.spec.get("webhooks"):
        out.append(BlindSpot(pointer="#/webhooks", what="Webhooks",
                             why="Eingehende Webhook-Operationen werden nicht geprüft."))
    if version.startswith("3.2") or (version.startswith("3.") and version not in ("3.0", "3.1")
                                      and not version.startswith(("3.0.", "3.1."))):
        out.append(BlindSpot(pointer="#/openapi", what=f"OpenAPI {version}",
                             why="Neuere Version als 3.1 — Konstrukte, die es dort nicht gab, sind oben einzeln aufgeführt."))
    return out


# ============================================================= Ausführung


def run_rules(ctx: AuditContext) -> list[Finding]:
    """Wendet alle Regeln an, dedupliziert, aggregiert und sortiert."""
    roh: list[Finding] = []
    for r in _DOKUMENT_REGELN:
        roh.extend(r(ctx))
    for cep in ctx.endpoints:
        for r in _ENDPUNKT_REGELN:
            roh.extend(r(ctx, cep))
    return aggregate(roh, gesamt=len(ctx.endpoints), immer=IMMER_AGGREGAT)


def check_ids() -> list[str]:
    """Alle Regelkennungen — ermittelt aus dem Quelltext der Regeln, nicht gepflegt."""
    import ast
    import inspect

    quelle = inspect.getsource(inspect.getmodule(run_rules))
    ids: set[str] = set()
    for k in ast.walk(ast.parse(quelle)):
        if isinstance(k, ast.keyword) and k.arg == "check_id" and isinstance(k.value, ast.Constant):
            ids.add(str(k.value.value))
    return sorted(ids)
