"""Prüfregeln für eine Gateway-Konfiguration.

Der Unterschied zur Spec-Analyse ist der Grund, warum es dieses Paket gibt: eine
OpenAPI-Spezifikation sagt, was eine Schnittstelle tun soll — die Gateway-
Konfiguration sagt, was sie tatsächlich tut. Ein Befund von hier ist deshalb
eine Feststellung, keine Vermutung.

Zwei Regeln gelten für den ganzen Katalog:

1. Kein Befund stützt sich auf ``PolicyAction.active_flag``. Das Feld steht in
   Exporten durchgehend auf ``False`` und ist ein Serialisierungsartefakt; eine
   Regel darauf träfe jede API und wäre reines Rauschen.
2. Eine Regel, die bei mehr als der Hälfte aller APIs anschlägt, beschreibt eine
   Betriebsgewohnheit und keine Schwachstelle. Sie wird zu einem Aggregat
   zusammengefasst (siehe :func:`run_rules`) statt N-mal einzeln gemeldet.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from oas_audit.findings import Confidence, Evidence, Finding, RuntimeGap, Scope, aggregate
from oas_audit.models import OWASPCategory, Severity

from wm_audit.models import GatewayApi, GatewayExport

#: Ab diesem Anteil betroffener APIs wird eine Regel aggregiert gemeldet.
AGGREGAT_SCHWELLE = 0.5

Regel = Callable[[GatewayApi], Iterable[Finding]]
_REGELN: list[Regel] = []


def regel(fn: Regel) -> Regel:
    _REGELN.append(fn)
    return fn


def _f(api: GatewayApi, **kw) -> Finding:
    kw.setdefault("scope", Scope.API)
    kw.setdefault("subject", api.label)
    return Finding(**kw)


def ohne_zugangsdaten(uri: str) -> str:
    """``http://user:pw@host/x`` → ``http://***@host/x``.

    Ein Routing-Ziel oder Alias kann Zugangsdaten in der URL tragen. In einen
    Bericht, der weitergegeben wird, gehören sie nicht.
    """
    i = uri.find("://")
    if i < 0:
        return uri
    start = i + 3
    ende = len(uri)
    for z in "/?#":
        j = uri.find(z, start)
        if j >= 0:
            ende = min(ende, j)
    at = uri.rfind("@", start, ende)
    if at < 0:
        return uri
    return uri[:start] + "***" + uri[at:]


# --------------------------------------------------------------- Identität

@regel
def keine_identify_policy(api: GatewayApi):
    """Ohne „Identify & Authorize“ nimmt das Gateway jeden Aufrufer an."""
    if api.has_action("evaluatePolicy"):
        return
    yield _f(
        api,
        check_id="gw.no_identify_policy",
        title="API ohne Identify-and-Authorize-Policy",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API2,
        reason=(
            "Für diese API ist keine Identify-and-Authorize-Policy konfiguriert. "
            "Das Gateway identifiziert den Aufrufer damit nicht und reicht jede "
            "Anfrage an das Backend weiter."
        ),
        remediation=(
            "Im Policy-Stage „Identify and Access“ eine Identify-and-Authorize-Policy "
            "einrichten. Ist die API bewusst öffentlich, sollte das dokumentiert und "
            "durch Threat-Protection und Rate-Limits abgesichert sein."
        ),
        evidence=[Evidence(
            pointer=api.source_path,
            excerpt="policyActions: " + ", ".join(sorted({a.template_key for a in api.policy_actions})),
            note="kein evaluatePolicy vorhanden",
        )],
    )


@regel
def anonymer_zugriff(api: GatewayApi):
    """``allowAnonymous`` hebt die Identifikation wieder auf."""
    for a in api.actions("evaluatePolicy"):
        if (a.value("allowAnonymous") or "").lower() == "true":
            yield _f(
                api,
                check_id="gw.anonymous_allowed",
                title="Identify-Policy erlaubt anonymen Zugriff",
                confidence=Confidence.BELEGT,
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.API2,
                reason=(
                    "Die Identify-and-Authorize-Policy ist konfiguriert, lässt über "
                    "allowAnonymous aber Anfragen ohne Identifikation durch. Die Policy "
                    "sieht in der Oberfläche vorhanden aus und greift trotzdem nicht."
                ),
                remediation="allowAnonymous auf false setzen.",
                evidence=[Evidence(pointer=f"{api.source_path} → {a.name}",
                                   excerpt="allowAnonymous: true")],
            )


@regel
def identifikation_oder_verknuepft(api: GatewayApi):
    """Mehrere Identifier mit ODER — das schwächste Glied entscheidet."""
    for a in api.actions("evaluatePolicy"):
        rules = a.groups("IdentificationRule")
        if len(rules) < 2 or (a.value("logicalConnector") or "").upper() != "OR":
            continue
        typen = [t for r in rules for t in a.group_values(r, "identificationType")]
        yield _f(
            api,
            check_id="gw.identify_or",
            title="Mehrere Identifikationsverfahren sind ODER-verknüpft",
            confidence=Confidence.BELEGT,
            severity=Severity.HIGH,
            owasp=OWASPCategory.API2,
            reason=(
                f"Die Policy akzeptiert {' oder '.join(typen)} — es genügt also das "
                "schwächste dieser Verfahren. Wo API-Key *und* Token gemeint waren, "
                "reicht dann der API-Key allein."
            ),
            remediation=(
                "logicalConnector auf AND setzen, wenn beide Nachweise verlangt sind. "
                "Ist ODER beabsichtigt, muss jedes einzelne Verfahren für sich als "
                "ausreichend gelten."
            ),
            evidence=[Evidence(pointer=f"{api.source_path} → {a.name}",
                               excerpt=f"logicalConnector: OR, identificationType: {', '.join(typen)}")],
        )


#: Verfahren, die eine Anwendung ausweisen, nicht einen Benutzer. ``hostNameAddress``
#: ist der Wert aus der offiziellen IBM-Postman-Collection; ``hostName`` bleibt für
#: ältere Fixtures erhalten.
NUR_ANWENDUNG = {"apiKey", "hostNameAddress", "hostName", "ipAddressRange"}


@regel
def nur_application_identitaet(api: GatewayApi):
    """API-Key identifiziert eine Anwendung, nicht einen Benutzer."""
    for a in api.actions("evaluatePolicy"):
        rules = a.groups("IdentificationRule")
        typen = {t for r in rules for t in a.group_values(r, "identificationType")}
        if typen and typen <= NUR_ANWENDUNG:
            yield _f(
                api,
                check_id="gw.application_identity_only",
                title="Nur Anwendungs-Identifikation, keine Benutzer-Authentifizierung",
                confidence=Confidence.WAHRSCHEINLICH,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API2,
                reason=(
                    f"Identifiziert wird ausschließlich über {', '.join(sorted(typen))}. "
                    "Das weist eine Anwendung aus, nicht den handelnden Benutzer — jede "
                    "benutzerbezogene Autorisierung muss dann vollständig im Backend "
                    "stattfinden."
                ),
                remediation=(
                    "Prüfen, ob das Backend die Benutzeridentität selbst auswertet. "
                    "Für benutzerbezogene Daten zusätzlich OAuth2 oder JWT verlangen."
                ),
                evidence=[Evidence(pointer=f"{api.source_path} → {a.name}",
                                   excerpt=f"identificationType: {', '.join(sorted(typen))}")],
            )


# --------------------------------------------------------------- Transport

@regel
def http_erlaubt(api: GatewayApi):
    """Das Gateway nimmt unverschlüsselte Anfragen an."""
    for a in api.actions("entryProtocolPolicy"):
        protos = [p.lower() for p in a.values("protocol")]
        if "http" in protos:
            yield _f(
                api,
                check_id="gw.http_allowed",
                title="Gateway akzeptiert unverschlüsseltes HTTP",
                confidence=Confidence.BELEGT,
                severity=Severity.HIGH,
                owasp=OWASPCategory.API8,
                reason=(
                    "Die Entry-Protocol-Policy lässt HTTP zu. Zugangsdaten und Nutzdaten "
                    "sind auf dem Weg zum Gateway mitlesbar."
                ),
                remediation="Nur HTTPS zulassen und HTTP an der Kante umleiten oder abweisen.",
                evidence=[Evidence(pointer=f"{api.source_path} → {a.name}",
                                   excerpt=f"protocol: {', '.join(protos)}")],
            )


def _klartext(api: GatewayApi, uri: str, evidence: Evidence) -> Finding:
    return _f(
        api,
        check_id="gw.plaintext_backend",
        title="Weiterleitung an ein Klartext-Backend",
        confidence=Confidence.BELEGT,
        severity=Severity.HIGH,
        owasp=OWASPCategory.API8,
        reason=(
            f"Das Gateway leitet an {uri} weiter. Die Verbindung endet damit "
            "am Gateway; im internen Netz laufen die Daten im Klartext."
        ),
        remediation="Das Backend über HTTPS ansprechen.",
        evidence=[evidence],
    )


@regel
def klartext_backend(api: GatewayApi):
    """Hinter dem Gateway geht es unverschlüsselt weiter.

    Maßgeblich ist das Ziel der Routing-Policy. ``nativeEndpoint`` enthält die
    Server der importierten Spec — eine Spec mit ``http``- *und* ``https``-Server
    wird über HTTPS geroutet und ist kein Befund. Nur ohne jede Routing-Policy
    (ältere Exporte) dient ``nativeEndpoint`` als Ersatz. Ist ein anderes
    Routing als ``straightThroughRouting`` zugeordnet, schweigt die Regel —
    dessen Ziel ist nicht belegt.
    """
    if api.hat_routing():
        for a, konfiguriert, aufgeloest in api.routing_ziele():
            if not aufgeloest.lower().startswith("http://"):
                continue
            uri = ohne_zugangsdaten(aufgeloest)
            yield _klartext(api, uri, Evidence(
                pointer=f"{api.source_path} → {a.name}",
                excerpt=f"endpointUri: {ohne_zugangsdaten(konfiguriert)}",
                note="" if konfiguriert == aufgeloest else f"über Alias aufgelöst: {uri}",
            ))
        return
    for ep in api.native_endpoints:
        if ep.is_plaintext:
            uri = ohne_zugangsdaten(ep.uri)
            yield _klartext(api, uri, Evidence(pointer=api.source_path,
                                               excerpt=f"nativeEndpoint: {uri}"))


@regel
def security_header_durchgereicht(api: GatewayApi):
    """``passSecurityHeaders`` reicht Zugangsdaten ans Backend weiter."""
    for ep in api.native_endpoints:
        if ep.pass_security_headers:
            yield _f(
                api,
                check_id="gw.pass_security_headers",
                title="Security-Header werden an das Backend durchgereicht",
                confidence=Confidence.WAHRSCHEINLICH,
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
                reason=(
                    "Authorization- und weitere Security-Header des Aufrufers gehen "
                    "unverändert an das Backend. Vertraut das Backend ihnen, entscheidet "
                    "am Ende der Aufrufer über seine eigene Berechtigung."
                ),
                remediation=(
                    "Prüfen, ob das Backend die durchgereichten Header auswertet. Wenn "
                    "nicht benötigt, passSecurityHeaders abschalten."
                ),
                evidence=[Evidence(pointer=api.source_path,
                                   excerpt=f"passSecurityHeaders: true ({ohne_zugangsdaten(ep.uri)})")],
            )


# ------------------------------------------------------- Betrieb und Daten

#: ``throttle`` ist der templateKey der Policy „Traffic Optimization“ im offiziellen
#: IBM-Repo (ibm-wm-transition/webmethods-api-gateway). Die übrigen Schlüssel bleiben
#: aus Kompatibilität mit älteren Fixtures erhalten.
TRAFFIC_LIMIT = ("throttle", "throttlingPolicy", "trafficOptimizationPolicy", "requestSizeLimit")


@regel
def fehlende_threat_protection(api: GatewayApi):
    """Ohne Größen- und Mengenbegrenzung ist die API leicht überlastbar."""
    if any(api.has_action(k) for k in TRAFFIC_LIMIT):
        return
    yield _f(
        api,
        check_id="gw.no_traffic_limit",
        title="Keine Begrenzung von Anfragemenge oder Nachrichtengröße",
        confidence=Confidence.WAHRSCHEINLICH,
        severity=Severity.MEDIUM,
        owasp=OWASPCategory.API4,
        reason=(
            "Auf API-Ebene ist keine Traffic-Begrenzung konfiguriert. Eine global "
            "gesetzte Threat-Protection kann greifen — sie ist in diesem Export "
            "jedoch nicht enthalten und daher hier nicht nachweisbar."
        ),
        remediation=(
            "Eine Traffic-Monitoring-Policy je API setzen oder die globale "
            "Threat-Protection-Konfiguration mit exportieren und prüfen."
        ),
        evidence=[Evidence(pointer=api.source_path,
                           excerpt="keine Traffic-Optimization-Policy (throttle)")],
    )


@regel
def log_invocation(api: GatewayApi):
    """Mitgeschriebene Nutzdaten sind ein Datenschutzthema."""
    for a in api.actions("logInvocation"):
        yield _f(
            api,
            check_id="gw.log_invocation",
            title="Log-Invocation-Policy aktiv",
            confidence=Confidence.WAHRSCHEINLICH,
            severity=Severity.LOW,
            owasp=OWASPCategory.API8,
            reason=(
                "Anfragen werden protokolliert. Sind Nutzdaten eingeschlossen, landen "
                "personenbezogene Daten und Zugangsdaten in den Logs."
            ),
            remediation=(
                "Prüfen, welche Bestandteile protokolliert werden, und Nutzdaten nur "
                "mit dokumentiertem Zweck und Löschfrist aufzeichnen."
            ),
            evidence=[Evidence(pointer=f"{api.source_path} → {a.name}", excerpt="logInvocation")],
        )


# ------------------------------------------------------------ Laufzeitgrenze

#: Was auch die Konfiguration nicht beantwortet. Wird gezählt und benannt,
#: niemals bewertet — die ehrliche Kehrseite jeder statischen Analyse.
LAUFZEIT_LUECKEN: list[RuntimeGap] = [
    RuntimeGap(key="key_verification", title="Wird ein erfundener API-Key tatsächlich abgewiesen?",
               owasp=OWASPCategory.API2,
               why="Ob die Policy im Betrieb greift, zeigt erst eine Anfrage."),
    RuntimeGap(key="jwt_signature", title="Wird die JWT-Signatur wirklich geprüft?",
               owasp=OWASPCategory.API2,
               why="Die Konfiguration nennt das Verfahren, nicht dessen Umsetzung."),
    RuntimeGap(key="object_authorization", title="Erreicht ein Aufrufer fremde Objekte?",
               owasp=OWASPCategory.API1,
               why="Objektbezogene Berechtigung liegt im Backend und braucht zwei Identitäten."),
    RuntimeGap(key="role_enforcement", title="Wird die Rollenprüfung durchgesetzt?",
               owasp=OWASPCategory.API5,
               why="Das Gateway identifiziert; autorisieren muss das Backend."),
    RuntimeGap(key="trust_header", title="Lässt sich ein Trust-Header fälschen?",
               owasp=OWASPCategory.API2,
               why="Hängt davon ab, wie das Backend eingehende Header behandelt."),
    RuntimeGap(key="global_threat_protection", title="Greift eine globale Threat-Protection?",
               owasp=OWASPCategory.API4,
               why="Globale Konfiguration liegt außerhalb des API-Exports."),
    RuntimeGap(key="security_headers", title="Werden Security-Header in Antworten gesetzt?",
               owasp=OWASPCategory.API8,
               why="Antwort-Header stehen in keiner Konfigurationsdatei."),
    RuntimeGap(key="cors", title="Wie verhält sich CORS tatsächlich?",
               owasp=OWASPCategory.API8,
               why="Erst eine Preflight-Anfrage zeigt die wirksame Regel."),
]


# ----------------------------------------------------------------- Ausführung

def run_rules(export: GatewayExport) -> list[Finding]:
    """Wendet alle Regeln an und fasst allgegenwärtige Befunde zusammen.

    Doppelte Befunde werden zusammengeführt: ein Verzeichnis kann mehrere
    Exporte enthalten, in denen dieselbe API erneut auftaucht (etwa je
    Umgebung). Unterscheiden sich die Konfigurationen, unterscheiden sich auch
    die Befunde und bleiben beide erhalten — identische verschmelzen zu einem.
    """
    roh: list[Finding] = []
    for api in export.apis:
        for r in _REGELN:
            roh.extend(r(api))

    # Der Anteil bezieht sich auf eindeutige APIs, nicht auf gelesene Dateien.
    gesamt = len({a.label for a in export.apis})
    return aggregate(roh, gesamt=gesamt, schwelle=AGGREGAT_SCHWELLE)
