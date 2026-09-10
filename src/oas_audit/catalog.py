"""Testfall-Katalog — was an dieser Spezifikation zu testen wäre, im Klartext.

Das Kernversprechen des Werkzeugs. Kein Anbieter im Feld leitet aus einer
konkreten Spezifikation einen lesbaren Security-Prüfsatz ab; die Regeln oben
sind Commodity, dieser Katalog ist es nicht.

Jeder Testfall hat Vorbedingung, Schritte, erwartetes Verhalten und das Signal,
an dem man einen Befund erkennt. **Ohne ausführbare Payloads** — das ist
zugleich der Moat-Schnitt (ausführbar = Pro) und die Missbrauchsgrenze: Der
Katalog ist eine Verteidigungs-Checkliste mit sicherem Sollverhalten, kein
Angriffsplan. Die Vorlagen sind deterministisch; gleiche Spezifikation, gleicher
Katalog. Kein Sprachmodell.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, Field

from oas_audit.findings import Confidence, Finding, Scope
from oas_audit.models import ClassifiedEndpoint, OWASPCategory
from oas_audit.rules import (
    _WRITE,
    AuditContext,
    _admin_praefix,
    _ist_auth_flow,
    _schema_name,
    _sensibel_in_antwort,
)
from oas_audit.sensitive import Kategorie, schemata

Lang = Literal["de", "en"]

CONTROLS = {
    OWASPCategory.API1: ["OWASP API1:2023"],
    OWASPCategory.API2: ["OWASP API2:2023"],
    OWASPCategory.API3: ["OWASP API3:2023"],
    OWASPCategory.API4: ["OWASP API4:2023"],
    OWASPCategory.API5: ["OWASP API5:2023"],
    OWASPCategory.API8: ["OWASP API8:2023"],
    OWASPCategory.API9: ["OWASP API9:2023"],
}
#: Jeder Testfall erfüllt inhaltlich ISO/IEC 27001:2022 8.29 (dokumentierter Testplan
#: mit erwartetem Ergebnis) und unterstützt § 30 Abs. 2 Nr. 5 BSIG. Bezug, keine Konformität.
ALLGEMEINE_CONTROLS = ["ISO/IEC 27001:2022 8.29", "§ 30 Abs. 2 Nr. 5 BSIG"]


class TestCase(BaseModel):
    id: str = ""
    key: str
    owasp: OWASPCategory
    #: 1 = zuerst prüfen (belegte Befunde, Objektzugriff auf sensible Daten, Admin),
    #: 2 = je Operation, 3 = einmal je API.
    priority: int
    scope: Scope = Scope.ENDPUNKT
    method: str | None = None
    path: str = ""
    title: str
    precondition: str
    steps: list[str]
    expected: str
    fail_signal: str
    #: Was die statische Analyse dazu schon sagt: belegt (der Test bestätigt einen
    #: dokumentierten Befund), wahrscheinlich (der Test entscheidet einen Hinweis)
    #: oder laufzeit (nur hier prüfbar).
    static_state: Confidence = Confidence.LAUFZEIT
    related_check: str | None = None
    #: Weitere Operationen, für die derselbe Testfall gilt.
    also_applies_to: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)

    @property
    def operation(self) -> str:
        return f"{self.method} {self.path}" if self.method else (self.path or "API")


def _id(key: str, method: str | None, path: str) -> str:
    return hashlib.sha1(f"{key}|{method or ''}|{path}".encode()).hexdigest()[:10]  # noqa: S324


class _Texte:
    """Zweisprachige Texte an einer Stelle — damit DE und EN nie auseinanderlaufen."""

    def __init__(self, lang: Lang) -> None:
        self.lang = lang

    def __call__(self, de: str, en: str) -> str:
        return de if self.lang == "de" else en


def build_catalog(ctx: AuditContext, findings: list[Finding], lang: Lang = "de") -> list[TestCase]:
    t = _Texte(lang)
    belegt = {(f.check_id, f.method, f.subject) for f in findings if f.confidence is Confidence.BELEGT}
    belegt_pfad = {(f.check_id, f.subject) for f in findings if f.confidence is Confidence.BELEGT}
    hinweis_betroffen: dict[str, set[str]] = {}
    for f in findings:
        if f.confidence is Confidence.WAHRSCHEINLICH:
            ziele = set(f.affected) | {f.subject}
            hinweis_betroffen.setdefault(f.check_id, set()).update(ziele)

    def zustand(check: str, ep: ClassifiedEndpoint | None, method: str | None = None, path: str = "") -> Confidence:
        if ep is not None:
            method, path = ep.endpoint.method.value, ep.endpoint.path
        if not path:
            return Confidence.LAUFZEIT
        if (check, method, path) in belegt or (check, path) in belegt_pfad:
            return Confidence.BELEGT
        ziele = hinweis_betroffen.get(check, set())
        hint = (ep.resource_hint or "") if ep else ""
        if path in ziele or f"{method} {path}" in ziele or (hint and hint in ziele) \
           or any(z.endswith(" " + path) for z in ziele):
            return Confidence.WAHRSCHEINLICH
        return Confidence.LAUFZEIT

    faelle: list[TestCase] = []

    def add(key: str, owasp: OWASPCategory, prio: int, *, ep: ClassifiedEndpoint | None = None,
            method: str | None = None, path: str = "", title: str, pre: str, steps: list[str],
            expected: str, fail: str, check: str | None = None, state: Confidence | None = None,
            also: Iterable[str] = ()) -> TestCase:
        if ep is not None:
            method, path = ep.endpoint.method.value, ep.endpoint.path
        st = state if state is not None else (zustand(check, ep, method, path) if check else Confidence.LAUFZEIT)
        tc = TestCase(
            id=_id(key, method, path), key=key, owasp=owasp, priority=prio,
            scope=Scope.ENDPUNKT if (method or path) else Scope.DOKUMENT,
            method=method, path=path, title=title, precondition=pre, steps=steps,
            expected=expected, fail_signal=fail, static_state=st, related_check=check,
            also_applies_to=sorted(set(also)), controls=CONTROLS[owasp] + ALLGEMEINE_CONTROLS,
        )
        faelle.append(tc)
        return tc

    eps = ctx.endpoints
    secured = [c for c in eps if c.endpoint.requires_auth]
    hat_bearer = any(s.get("type") == "http" and str(s.get("scheme", "")).lower() == "bearer"
                     for s in ctx.security_schemes.values() if isinstance(s, dict))
    hat_apikey_query = any(s.get("type") == "apiKey" and str(s.get("in", "")).lower() == "query"
                           for s in ctx.security_schemes.values() if isinstance(s, dict))
    wm = any(f.check_id == "gateway.wm_detected" for f in findings)

    # ------------------------------------------------------------ Belegte Befunde bestätigen
    for cep in eps:
        e = cep.endpoint
        if e.requires_auth or _ist_auth_flow(e):
            continue  # ein belegter Befund entscheidet, nicht der Pfadname (auch /debug/health)
        checks = [c for c in ("endpoint.unauth_sensitive_response", "endpoint.admin_path",
                              "endpoint.debug_path", "endpoint.unauth_write", "endpoint.unauth_id_read")
                  if (c, e.method.value, e.path) in belegt]
        if not checks:
            continue
        add("confirm.unauthenticated", _owasp_for(checks[0]), 1, ep=cep, check=checks[0],
            title=t("Dokumentierte Erreichbarkeit ohne Authentifizierung bestätigen",
                    "Confirm documented reachability without authentication"),
            pre=t("Kein Token, kein API-Key. Die Spezifikation deklariert für diese Operation keine Absicherung.",
                  "No token, no API key. The specification declares no security for this operation."),
            steps=[t(f"{e.method.value} {e.path} ohne jede Authentifizierung aufrufen.",
                     f"Call {e.method.value} {e.path} without any authentication."),
                   t("Antwortstatus und Antwortinhalt festhalten.", "Record status and response body.")],
            expected=t("401 oder 403. Ist die Operation bewusst öffentlich, muss das dokumentiert sein und der Inhalt darf keine sensiblen Felder enthalten.",
                       "401 or 403. If the operation is intentionally public, that must be documented and the body must contain no sensitive fields."),
            fail=t("200 mit Daten — die Spezifikation beschreibt die Offenlegung korrekt, das System setzt sie um.",
                   "200 with data — the specification describes the exposure correctly and the system implements it."))

    # ------------------------------------------------------------ API2 Authentifizierung
    nach_pfad: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in secured:
        nach_pfad.setdefault(cep.endpoint.path, []).append(cep)
    for pfad, ceps in nach_pfad.items():
        methoden = ", ".join(c.endpoint.method.value for c in ceps)
        add("auth.enforced", OWASPCategory.API2, 2, method=None, path=pfad,
            also=[f"{c.endpoint.method.value} {pfad}" for c in ceps],
            title=t("Authentifizierung wird durchgesetzt", "Authentication is enforced"),
            pre=t(f"Ein gültiges Token für Vergleichszwecke. Dokumentierte Methoden: {methoden}.",
                  f"A valid token for comparison. Documented methods: {methoden}."),
            steps=[t("Jede Methode ohne Authentifizierung aufrufen.", "Call each method without authentication."),
                   t("Mit syntaktisch ungültigem Token aufrufen (z. B. verkürzt oder verändert).",
                     "Call with a syntactically invalid token (e.g. truncated or altered)."),
                   t("Mit abgelaufenem Token aufrufen.", "Call with an expired token."),
                   t("Mit gültigem Token aufrufen (Kontrolle).", "Call with a valid token (control).")],
            expected=t("Die ersten drei Aufrufe liefern 401, der vierte 2xx. Fehlerantworten enthalten keine Details zur Prüflogik.",
                       "The first three calls return 401, the fourth 2xx. Error responses reveal nothing about the validation logic."),
            fail=t("Ein 2xx ohne gültiges Token — oder ein 500, das auf eine Ausnahme in der Token-Prüfung deutet.",
                   "A 2xx without a valid token — or a 500 hinting at an exception in token validation."))

    for cep in secured:
        e = cep.endpoint
        if e.has_alternative_auth:
            namen = [" + ".join(r.name or r.scheme or r.type for r in g) for g in e.security_alternatives]
            add("auth.alternatives", OWASPCategory.API2, 1, ep=cep, check="spec.security_or_semantics",
                title=t("Jedes alternative Verfahren einzeln prüfen (ODER-Verknüpfung)",
                        "Check each alternative scheme on its own (OR semantics)"),
                pre=t(f"Die Operation akzeptiert {len(namen)} Verfahren alternativ: {' | '.join(namen)}.",
                      f"The operation accepts {len(namen)} schemes as alternatives: {' | '.join(namen)}."),
                steps=[t(f"Nur mit „{n}“ aufrufen, alle anderen Nachweise weglassen.",
                         f"Call with “{n}” only, omitting all other credentials.") for n in namen]
                      + [t("Prüfen, ob jedes Verfahren für sich den Zugriff vollständig rechtfertigt.",
                           "Check whether each scheme alone fully justifies the access.")],
                expected=t("Entweder ist jedes Verfahren allein bewusst ausreichend (dokumentiert) — oder die Operation verlangt beide und lehnt Einzelnachweise mit 401 ab.",
                           "Either each scheme alone is intentionally sufficient (documented) — or the operation requires both and rejects single credentials with 401."),
                fail=t("Ein schwaches Verfahren (z. B. API-Key ohne Benutzer-Token) genügt, obwohl beide gemeint waren.",
                       "A weak scheme (e.g. API key without user token) suffices although both were intended."))

    if hat_bearer and secured:
        beispiel = secured[0].endpoint
        add("auth.jwt_unsigned", OWASPCategory.API2, 1, path="", check=None,
            title=t("Unsigniertes oder umsigniertes Token wird abgewiesen",
                    "Unsigned or re-signed token is rejected"),
            pre=t(f"Ein gültiges Bearer-Token; eine geschützte Operation wie {beispiel.method.value} {beispiel.path}.",
                  f"A valid bearer token; a protected operation such as {beispiel.method.value} {beispiel.path}."),
            steps=[t("Das Token so verändern, dass die Signatur fehlt (Algorithmus „none“).",
                     "Alter the token so that the signature is missing (algorithm “none”)."),
                   t("Das Token mit einem anderen Schlüssel neu signieren.", "Re-sign the token with a different key."),
                   t("Einen Anspruch im Token ändern (z. B. Benutzer-ID oder Rolle), Signatur unverändert lassen.",
                     "Change a claim in the token (e.g. user id or role) leaving the signature untouched."),
                   t("Jeweils die geschützte Operation aufrufen.", "Call the protected operation each time.")],
            expected=t("Alle Varianten: 401.", "All variants: 401."),
            fail=t("Ein 2xx — das Backend prüft die Signatur nicht oder akzeptiert „none“.",
                   "A 2xx — the backend does not verify the signature or accepts “none”."))

    if hat_apikey_query:
        add("auth.apikey_query", OWASPCategory.API8, 2, path="", check="spec.api_key_in_query",
            state=Confidence.BELEGT,
            title=t("API-Key im Query-String landet in Logs", "API key in the query string ends up in logs"),
            pre=t("Ein gültiger API-Key; Zugriff auf Server-, Proxy- oder Gateway-Logs.",
                  "A valid API key; access to server, proxy or gateway logs."),
            steps=[t("Eine Operation mit dem Key im Query-String aufrufen.", "Call an operation with the key in the query string."),
                   t("Logs auf den Klartext-Key durchsuchen.", "Search the logs for the plaintext key."),
                   t("Denselben Aufruf mit dem Key im Header wiederholen und prüfen, ob der Query-Weg abgeschaltet werden kann.",
                     "Repeat with the key in a header and check whether the query path can be disabled.")],
            expected=t("Der Key erscheint in keinem Log; idealerweise wird der Query-Weg abgewiesen.",
                       "The key appears in no log; ideally the query path is rejected."),
            fail=t("Der Key steht im Klartext in Access-Logs oder Referer-Headern.",
                   "The key appears in plaintext in access logs or referer headers."))

    # ------------------------------------------------------------ API1 Objektberechtigung
    objekt_pfade: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in secured:
        if cep.id_like_parameter is not None:
            objekt_pfade.setdefault(cep.endpoint.path, []).append(cep)
    for pfad, ceps in objekt_pfade.items():
        cep = ceps[0]
        e = cep.endpoint
        felder: dict[Kategorie, list[str]] = {}
        for c in ceps:
            for kat, namen in _sensibel_in_antwort(c.endpoint).items():
                felder.setdefault(kat, []).extend(namen)
        sensibel = bool(felder.get(Kategorie.FINANZ) or felder.get(Kategorie.PII) or felder.get(Kategorie.CREDENTIAL))
        p = cep.id_like_parameter.name
        schreibend = any(c.endpoint.method in _WRITE for c in ceps)
        methoden = ", ".join(c.endpoint.method.value for c in ceps)
        add("bola.cross_user", OWASPCategory.API1, 1 if (sensibel or schreibend) else 2, method=None, path=pfad,
            check="endpoint.object_level_access", also=[f"{c.endpoint.method.value} {pfad}" for c in ceps],
            title=t("Fremdes Objekt per ID anfordern (BOLA)", "Request another user's object by id (BOLA)"),
            pre=t(f"Zwei Konten A und B mit gültigen Tokens; ein Wert für „{p}“, der zu B gehört. Methoden: {methoden}.",
                  f"Two accounts A and B with valid tokens; a value for “{p}” that belongs to B. Methods: {methoden}."),
            steps=[t(f"Mit dem Token von A jede Methode auf {pfad} mit der ID von B aufrufen.",
                     f"With A's token call each method on {pfad} using B's id."),
                   t("Bei Mandantenfähigkeit: dasselbe mit einem Konto eines anderen Mandanten.",
                     "For multi-tenant systems: repeat with an account from another tenant."),
                   t("Bei schreibenden Methoden anschließend prüfen, ob sich B's Objekt verändert hat.",
                     "For write methods, afterwards check whether B's object changed.") if schreibend
                   else t("Antwortinhalt prüfen: enthält er Daten von B?", "Inspect the body: does it contain B's data?")],
            expected=t("403 oder 404 — nie 200 mit Daten oder Wirkung auf B's Objekt.",
                       "403 or 404 — never 200 with data or an effect on B's object."),
            fail=t("200 mit Daten von B" + (" (darunter sensible Felder)" if sensibel else "") + " oder eine erfolgreiche Änderung.",
                   "200 with B's data" + (" (including sensitive fields)" if sensibel else "") + " or a successful change."))
        if (cep.id_like_parameter.schema_type or "").lower() in ("integer", "int32", "int64", "number"):
            add("bola.enumeration", OWASPCategory.API1, 2, ep=cep, check="endpoint.sequential_integer_id",
                title=t("IDs sind durchprobierbar", "Ids can be enumerated"),
                pre=t(f"Ein gültiges Token; „{p}“ ist eine ganze Zahl.", f"A valid token; “{p}” is an integer."),
                steps=[t("Die eigene ID um eins erhöhen und vermindern.", "Increment and decrement your own id."),
                       t("Einen kleinen Bereich (z. B. 20 Werte) durchgehen und Statuscodes zählen.",
                         "Walk a small range (e.g. 20 values) and count status codes.")],
                expected=t("Fremde IDs liefern 403/404; idealerweise sind IDs nicht erratbar (UUID).",
                           "Foreign ids return 403/404; ideally ids are not guessable (UUID)."),
                fail=t("Mehrere fremde Objekte sind erreichbar — aus einem Einzelfall wird ein Datenabzug.",
                       "Several foreign objects are reachable — a single case becomes a data dump."))

    # ------------------------------------------------------------ API5 Funktionsberechtigung
    admin_gruppen: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in secured:
        pr = _admin_praefix(cep.endpoint.path)
        if pr:
            admin_gruppen.setdefault(pr[0], []).append(cep)
    for praefix, ceps in admin_gruppen.items():
        ops = [f"{c.endpoint.method.value} {c.endpoint.path}" for c in ceps]
        first = ceps[0]
        add("bfla.admin_as_user", OWASPCategory.API5, 1, ep=first, check="endpoint.admin_path", also=ops[1:],
            title=t("Administrative Funktion mit gewöhnlichem Benutzer aufrufen",
                    "Call an administrative function as an ordinary user"),
            pre=t(f"Ein Token ohne Admin-Rolle. Unter {praefix} sind {len(ops)} Operationen dokumentiert.",
                  f"A token without the admin role. {len(ops)} operations are documented under {praefix}."),
            steps=[t("Jede dieser Operationen mit dem Nicht-Admin-Token aufrufen.", "Call each of these operations with the non-admin token."),
                   t("Bei schreibenden Operationen einen unschädlichen Wert verwenden und die Wirkung prüfen.",
                     "For write operations use a harmless value and check the effect."),
                   t("Dasselbe mit einem Token eines anderen Mandanten wiederholen.", "Repeat with a token from another tenant.")],
            expected=t("403 für jede Operation.", "403 for every operation."),
            fail=t("Ein 2xx — die Rollenprüfung fehlt oder greift nur in der Oberfläche.",
                   "A 2xx — the role check is missing or exists only in the UI."))

    write_ops = [c for c in secured if c.endpoint.method in _WRITE and not _ist_auth_flow(c.endpoint)
                 and _admin_praefix(c.endpoint.path) is None]
    write_pfade: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in write_ops:
        write_pfade.setdefault(cep.endpoint.path, []).append(cep)
    for pfad, ceps in write_pfade.items():
        methoden = ", ".join(c.endpoint.method.value for c in ceps)
        add("bfla.write_least_privilege", OWASPCategory.API5, 2, method=None, path=pfad,
            check="endpoint.write_without_scope", also=[f"{c.endpoint.method.value} {pfad}" for c in ceps],
            title=t("Schreibende Operation mit minimal berechtigtem Konto",
                    "Write operation with a least-privileged account"),
            pre=t(f"Ein Token mit der geringsten dokumentierten Berechtigung (Leserolle, eingeschränkter Scope). Methoden: {methoden}.",
                  f"A token with the least documented privilege (read-only role, restricted scope). Methods: {methoden}."),
            steps=[t(f"Jede schreibende Methode auf {pfad} mit diesem Token und einem unschädlichen Wert aufrufen.",
                     f"Call each write method on {pfad} with this token and a harmless value."),
                   t("Anschließend per Leseoperation prüfen, ob eine Änderung stattfand.",
                     "Afterwards verify via a read operation whether a change occurred.")],
            expected=t("403 — oder ein dokumentierter Grund, warum diese Rolle schreiben darf.",
                       "403 — or a documented reason why this role may write."),
            fail=t("Die Änderung ist wirksam, obwohl die Rolle es nicht dürfen sollte.",
                   "The change takes effect although the role should not be allowed."))

    # ------------------------------------------------------------ API3 Property-Level
    schema_gruppen: dict[str, dict[str, Any]] = {}
    for cep in secured:
        e = cep.endpoint
        for s in [s for code, s in e.response_schemas.items() if 200 <= code < 300]:
            felder = _sensibel_in_antwort(e)
            if not (felder.get(Kategorie.FINANZ) or felder.get(Kategorie.PII)):
                continue
            schluessel = _schema_name(s) or f"#{id(getattr(s, '__subject__', s))}"
            g = schema_gruppen.setdefault(schluessel, {"ceps": [], "felder": felder})
            g["ceps"].append(cep)
            break
    for g in schema_gruppen.values():
        ceps = g["ceps"]
        first = ceps[0]
        namen = [f for kat in (Kategorie.FINANZ, Kategorie.PII) for f in g["felder"].get(kat, [])][:6]
        add("bopla.response_fields", OWASPCategory.API3, 2 if g["felder"].get(Kategorie.FINANZ) else 3, ep=first,
            check="schema.sensitive_in_response",
            also=[f"{c.endpoint.method.value} {c.endpoint.path}" for c in ceps[1:]],
            title=t("Antwort enthält nur die Felder, die die Rolle sehen darf",
                    "Response contains only the fields the role may see"),
            pre=t(f"Tokens für jede dokumentierte Rolle. Das Antwort-Schema enthält u. a. {', '.join(namen)}.",
                  f"Tokens for every documented role. The response schema contains e.g. {', '.join(namen)}."),
            steps=[t("Die Operation mit jeder Rolle aufrufen und die Feldmenge vergleichen.",
                     "Call the operation with each role and compare the set of fields."),
                   t("Prüfen, ob Felder mit leerem Wert statt weggelassen zurückkommen (Struktur-Leak).",
                     "Check whether fields come back empty instead of omitted (structure leak).")],
            expected=t("Rollen mit geringerer Berechtigung sehen die sensiblen Felder nicht — sie fehlen, statt leer zu sein.",
                       "Lower-privileged roles do not see the sensitive fields — they are absent, not empty."),
            fail=t("Jede Rolle erhält das vollständige Objekt.", "Every role receives the full object."))

    ma_pfade: dict[str, list[ClassifiedEndpoint]] = {}
    for cep in write_ops + [c for c in secured if c.endpoint.method in _WRITE and _admin_praefix(c.endpoint.path)]:
        e = cep.endpoint
        if not e.request_schema:
            continue
        if not any(s.get("type") == "object" or "properties" in s for _, s in schemata(e.request_schema)):
            continue
        ma_pfade.setdefault(e.path, []).append(cep)
    for pfad, ceps in ma_pfade.items():
        methoden = ", ".join(c.endpoint.method.value for c in ceps)
        add("bopla.mass_assignment", OWASPCategory.API3, 2, method=None, path=pfad,
            check="schema.additional_properties_open", also=[f"{c.endpoint.method.value} {pfad}" for c in ceps],
            title=t("Nicht dokumentiertes Feld wird ignoriert oder abgewiesen (Mass Assignment)",
                    "Undocumented field is ignored or rejected (mass assignment)"),
            pre=t(f"Ein gültiges Token; ein Feldname, der im Datenmodell plausibel, aber nicht im Request-Schema dokumentiert ist (z. B. Rolle, Status, Mandant, Freigabe). Methoden: {methoden}.",
                  f"A valid token; a field name that is plausible in the data model but not documented in the request schema (e.g. role, status, tenant, approval). Methods: {methoden}."),
            steps=[t(f"Jede Methode auf {pfad} mit gültigem Body plus diesem zusätzlichen Feld aufrufen.",
                     f"Call each method on {pfad} with a valid body plus this extra field."),
                   t("Das Objekt anschließend lesen und prüfen, ob das Feld übernommen wurde.",
                     "Read the object afterwards and check whether the field was adopted.")],
            expected=t("400/422 oder 2xx ohne Übernahme des Felds. Der gelesene Zustand zeigt den Wert nicht.",
                       "400/422 or 2xx without adopting the field. The read state does not show the value."),
            fail=t("Das Feld wurde übernommen — Rechte oder Zustände lassen sich vom Aufrufer setzen.",
                   "The field was adopted — the caller can set rights or states."))

    # ------------------------------------------------------------ API4 Ressourcen
    for cep in eps:
        e = cep.endpoint
        if ("endpoint.list_without_pagination", e.method.value, e.path) not in belegt and \
           e.path not in hinweis_betroffen.get("endpoint.list_without_pagination", set()):
            continue
        add("api4.list_bounded", OWASPCategory.API4, 2, ep=cep, check="endpoint.list_without_pagination",
            title=t("Listenantwort ist serverseitig begrenzt", "List response is bounded server-side"),
            pre=t("Ein Datenbestand mit deutlich mehr Objekten als eine sinnvolle Seite (z. B. > 1 000).",
                  "A data set with clearly more objects than a sensible page (e.g. > 1,000)."),
            steps=[t(f"GET {e.path} ohne Parameter aufrufen und die Anzahl der Elemente zählen.",
                     f"Call GET {e.path} without parameters and count the elements."),
                   t("Falls ein Limit-Parameter existiert: einen sehr großen Wert übergeben.",
                     "If a limit parameter exists: pass a very large value.")],
            expected=t("Die Antwort ist auf eine feste Obergrenze gedeckelt; größere Anfragen werden abgeschnitten oder abgewiesen.",
                       "The response is capped at a fixed maximum; larger requests are truncated or rejected."),
            fail=t("Der gesamte Bestand kommt in einer Antwort.", "The entire data set arrives in one response."))
    for cep in eps:
        e = cep.endpoint
        if ("endpoint.unbounded_upload", e.method.value, e.path) not in belegt and \
           e.path not in hinweis_betroffen.get("endpoint.unbounded_upload", set()):
            continue
        add("api4.upload_bounded", OWASPCategory.API4, 2, ep=cep, check="endpoint.unbounded_upload",
            title=t("Upload-Größe wird begrenzt", "Upload size is limited"),
            pre=t("Ein gültiges Token; eine Datei deutlich über der erwarteten Nutzgröße.",
                  "A valid token; a file well above the expected payload size."),
            steps=[t(f"{e.method.value} {e.path} mit der übergroßen Datei aufrufen.", f"Call {e.method.value} {e.path} with the oversized file."),
                   t("Einen nicht erlaubten Dateityp mit passender Endung senden.", "Send a disallowed file type with a matching extension.")],
            expected=t("413 bzw. 415, bevor die Datei vollständig übertragen ist.", "413 or 415 before the file is fully transferred."),
            fail=t("Der Upload wird angenommen oder der Server antwortet mit 500.", "The upload is accepted or the server responds with 500."))

    if any(f.check_id == "schema.no_constraints" for f in findings):
        betroffen = sorted(next(f.affected for f in findings if f.check_id == "schema.no_constraints"))
        add("api4.input_length", OWASPCategory.API4, 3, path="", check="schema.no_constraints",
            state=Confidence.WAHRSCHEINLICH, also=betroffen,
            title=t("Übergroße Eingaben werden sauber abgewiesen", "Oversized inputs are rejected cleanly"),
            pre=t(f"Ein gültiges Token. Betroffen: {len(betroffen)} schreibende Operationen ohne Längenbegrenzung im Schema.",
                  f"A valid token. Affected: {len(betroffen)} write operations without length constraints in the schema."),
            steps=[t("Einen String-Wert mit z. B. 1 MB Länge in ein dokumentiertes Feld senden.", "Send a string value of e.g. 1 MB into a documented field."),
                   t("Ein Array mit sehr vielen Elementen senden.", "Send an array with very many elements.")],
            expected=t("400/413/422 mit kurzer Fehlermeldung; keine Verzögerung anderer Anfragen.",
                       "400/413/422 with a short error message; no delay for other requests."),
            fail=t("500, Timeouts oder ein gespeicherter Wert in voller Länge.", "500, timeouts, or a stored value at full length."))

    add("api4.rate_limit", OWASPCategory.API4, 3, path="",
        title=t("Rate-Limit greift", "Rate limit takes effect"),
        pre=t("Ein gültiges Token; eine harmlose Leseoperation.", "A valid token; a harmless read operation."),
        steps=[t("Die Operation in kurzer Folge oft aufrufen (z. B. 100× in 10 s), Statuscodes zählen.",
                 "Call the operation many times in quick succession (e.g. 100× in 10 s), count status codes."),
               t("Dasselbe für eine Login- oder Token-Operation wiederholen, falls vorhanden.",
                 "Repeat for a login or token operation, if present.")],
        expected=t("Ab einer Schwelle 429 mit Retry-After; Login-Operationen deutlich strenger.",
                   "429 with Retry-After beyond a threshold; login operations noticeably stricter."),
        fail=t("Kein 429 — oder Latenz steigt, bis andere Nutzer betroffen sind.", "No 429 — or latency rises until other users are affected."))

    # ------------------------------------------------------------ API8 Konfiguration
    add("api8.cors", OWASPCategory.API8, 3, path="",
        title=t("CORS erlaubt nur bekannte Ursprünge", "CORS allows only known origins"),
        pre=t("Eine geschützte Operation; ein beliebiger fremder Ursprung.", "A protected operation; an arbitrary foreign origin."),
        steps=[t("Preflight (OPTIONS) mit fremdem Origin und Access-Control-Request-Method senden.",
                 "Send a preflight (OPTIONS) with a foreign Origin and Access-Control-Request-Method."),
               t("Antwort-Header Access-Control-Allow-Origin und -Credentials prüfen.",
                 "Inspect the Access-Control-Allow-Origin and -Credentials response headers."),
               t("Einen echten Request mit fremdem Origin senden.", "Send a real request with a foreign origin.")],
        expected=t("Kein Allow-Origin für unbekannte Ursprünge; nie „*“ zusammen mit Credentials.",
                   "No Allow-Origin for unknown origins; never “*” together with credentials."),
        fail=t("Fremder Origin wird gespiegelt oder „*“ mit Allow-Credentials: true.", "Foreign origin is reflected or “*” with Allow-Credentials: true."))
    add("api8.security_headers", OWASPCategory.API8, 3, path="",
        title=t("Security-Header sind gesetzt", "Security headers are set"),
        pre=t("Eine beliebige Antwort der API.", "Any response of the API."),
        steps=[t("Antwort-Header auf Strict-Transport-Security, X-Content-Type-Options, Cache-Control (no-store bei sensiblen Daten) und Content-Type prüfen.",
                 "Check response headers for Strict-Transport-Security, X-Content-Type-Options, Cache-Control (no-store for sensitive data) and Content-Type."),
               t("Server- und X-Powered-By-Header auf Versionsangaben prüfen.", "Check Server and X-Powered-By headers for version information.")],
        expected=t("Header vorhanden; keine Produkt- oder Versionsangaben.", "Headers present; no product or version information."),
        fail=t("Fehlende Header oder ein Banner wie „Server: Produkt/1.2.3“.", "Missing headers or a banner such as “Server: product/1.2.3”."))
    add("api8.error_disclosure", OWASPCategory.API8, 3, path="",
        title=t("Fehlerantworten verraten keine Interna", "Error responses reveal no internals"),
        pre=t("Ein gültiges Token; eine schreibende Operation mit Request-Body.", "A valid token; a write operation with a request body."),
        steps=[t("Ungültiges JSON senden.", "Send invalid JSON."),
               t("Einen falschen Datentyp in ein dokumentiertes Feld senden.", "Send a wrong data type into a documented field."),
               t("Eine nicht existierende ID anfordern.", "Request a non-existent id."),
               t("Antwortinhalt auf Stack-Traces, Dateipfade, SQL, Frameworknamen und Versionen prüfen.",
                 "Inspect bodies for stack traces, file paths, SQL, framework names and versions.")],
        expected=t("Kurze, einheitliche Fehlerobjekte mit Status 400/404/422.", "Short, uniform error objects with status 400/404/422."),
        fail=t("Stack-Trace, interner Pfad oder ein 500 mit Detailtext.", "Stack trace, internal path, or a 500 with detailed text."))
    if any(f.check_id == "spec.http_server" for f in findings):
        add("api8.tls_only", OWASPCategory.API8, 2, path="", check="spec.http_server", state=Confidence.BELEGT,
            title=t("HTTP wird nicht bedient", "HTTP is not served"),
            pre=t("Die dokumentierte http-Server-URL.", "The documented http server URL."),
            steps=[t("Eine geschützte Operation über http:// aufrufen, mit gültigem Token.", "Call a protected operation over http:// with a valid token."),
                   t("Prüfen, ob eine Antwort mit Daten kommt oder ein Redirect.", "Check whether data or a redirect comes back.")],
            expected=t("Verbindung abgewiesen oder Redirect ohne Verarbeitung der Anfrage; HSTS gesetzt.",
                       "Connection refused or redirect without processing the request; HSTS set."),
            fail=t("Daten über Klartext — das Token ist damit bereits übertragen worden.", "Data over plaintext — the token has already been transmitted."))

    # ------------------------------------------------------------ API9 Inventar
    if any(f.check_id == "spec.version_sprawl" for f in findings):
        add("api9.old_versions", OWASPCategory.API9, 2, path="", check="spec.version_sprawl", state=Confidence.BELEGT,
            title=t("Ältere API-Versionen haben denselben Sicherheitsstand", "Older API versions have the same security level"),
            pre=t("Die Testfälle dieses Katalogs für die aktuelle Version.", "The test cases of this catalogue for the current version."),
            steps=[t("Die Authentifizierungs- und Objektberechtigungs-Testfälle gegen die älteste dokumentierte Version wiederholen.",
                     "Repeat the authentication and object-authorization test cases against the oldest documented version."),
                   t("Prüfen, ob die alte Version ein Abschaltdatum kommuniziert (Sunset/Deprecation-Header).",
                     "Check whether the old version communicates a sunset date (Sunset/Deprecation headers).")],
            expected=t("Identisches Verhalten; alte Versionen kündigen ihr Ende an.", "Identical behaviour; old versions announce their end."),
            fail=t("Die alte Version akzeptiert, was die neue abweist.", "The old version accepts what the new one rejects."))
    crud = [c for c in eps if ("path.crud_method_gap", None, c.endpoint.path) in belegt_pfad
            or c.endpoint.path in hinweis_betroffen.get("path.crud_method_gap", set())]
    if crud:
        first = crud[0]
        add("api9.undocumented_methods", OWASPCategory.API9, 3, ep=first, check="path.crud_method_gap",
            also=[c.endpoint.path for c in crud[1:]],
            title=t("Nicht dokumentierte Methoden werden abgewiesen", "Undocumented methods are rejected"),
            pre=t("Ein gültiges Token; Objektpfade, für die nur GET dokumentiert ist.", "A valid token; object paths with only GET documented."),
            steps=[t("PUT, PATCH und DELETE auf den Pfad senden.", "Send PUT, PATCH and DELETE to the path."),
                   t("OPTIONS senden und den Allow-Header lesen.", "Send OPTIONS and read the Allow header.")],
            expected=t("405 für jede nicht dokumentierte Methode; Allow nennt nur dokumentierte.",
                       "405 for every undocumented method; Allow lists only documented ones."),
            fail=t("Eine nicht dokumentierte Methode verändert Daten.", "An undocumented method changes data."))
    add("api9.discovery", OWASPCategory.API9, 3, path="",
        title=t("Dokumentation und Diagnose-Endpunkte sind nicht öffentlich",
                "Documentation and diagnostic endpoints are not public"),
        pre=t("Kein Token.", "No token."),
        steps=[t("Typische Pfade ohne Token aufrufen: /openapi.json, /swagger, /docs, /api-docs, /actuator, /debug, /metrics, /health mit Details.",
                 "Call typical paths without a token: /openapi.json, /swagger, /docs, /api-docs, /actuator, /debug, /metrics, detailed /health."),
               t("Mit den dokumentierten Pfaden abgleichen.", "Compare with the documented paths.")],
        expected=t("404 oder 401, außer bewusst veröffentlichter Dokumentation.", "404 or 401, except deliberately published documentation."),
        fail=t("Ein Diagnose-Endpunkt liefert Konfiguration oder Umgebungsvariablen.", "A diagnostic endpoint returns configuration or environment variables."))

    # ------------------------------------------------------------ webMethods API Gateway
    if wm:
        gw = [c for c in eps if c.endpoint.path.startswith("/gateway/")] or secured[:1]
        first = gw[0] if gw else None
        add("gateway.key_without_user", OWASPCategory.API2, 1, ep=first, check="spec.security_or_semantics",
            title=t("API-Key ohne Benutzer-Token genügt nicht", "API key without user token is not sufficient"),
            pre=t("Ein gültiger Gateway-API-Key einer registrierten Anwendung; kein Benutzer-Token.",
                  "A valid gateway API key of a registered application; no user token."),
            steps=[t("Die Operation nur mit dem API-Key aufrufen.", "Call the operation with the API key only."),
                   t("Die Operation nur mit dem Benutzer-Token aufrufen.", "Call the operation with the user token only."),
                   t("Einen erfundenen API-Key mit gültigem Token verwenden.", "Use a made-up API key with a valid token.")],
            expected=t("401 in allen drei Fällen — Identify-and-Authorize ist UND-verknüpft und der Key wird gegen das Register geprüft.",
                       "401 in all three cases — Identify-and-Authorize is AND-linked and the key is checked against the registry."),
            fail=t("Ein Nachweis allein genügt, oder ein erfundener Key wird akzeptiert.", "One credential alone suffices, or a made-up key is accepted."))
        add("gateway.trust_header", OWASPCategory.API2, 1, ep=first,
            title=t("Trust-Header des Gateways lässt sich nicht fälschen", "Gateway trust header cannot be forged"),
            pre=t("Ein gültiger Aufruf; Kenntnis des Headers, mit dem das Gateway die Identität ans Backend gibt (z. B. X-User, X-Client-Id).",
                  "A valid call; knowledge of the header the gateway uses to pass identity to the backend (e.g. X-User, X-Client-Id)."),
            steps=[t("Denselben Header selbst mit einer fremden Identität setzen und über das Gateway aufrufen.",
                     "Set that header yourself with a foreign identity and call via the gateway."),
                   t("Das Backend direkt (nativer Endpunkt, ohne Gateway) mit gesetztem Header aufrufen.",
                     "Call the backend directly (native endpoint, bypassing the gateway) with the header set.")],
            expected=t("Das Gateway überschreibt Client-Header; das Backend ist ohne Gateway nicht erreichbar.",
                       "The gateway overwrites client headers; the backend is unreachable without the gateway."),
            fail=t("Die gefälschte Identität wird übernommen, oder der native Endpunkt antwortet.",
                   "The forged identity is adopted, or the native endpoint responds."))

    # Sortierung: Priorität, dann OWASP, dann Operation — stabil.
    faelle.sort(key=lambda c: (c.priority, c.owasp.value, c.path, c.method or ""))
    return faelle


def _owasp_for(check_id: str) -> OWASPCategory:
    return {
        "endpoint.unauth_sensitive_response": OWASPCategory.API3,
        "endpoint.admin_path": OWASPCategory.API5,
        "endpoint.debug_path": OWASPCategory.API8,
        "endpoint.unauth_write": OWASPCategory.API5,
        "endpoint.unauth_id_read": OWASPCategory.API1,
    }.get(check_id, OWASPCategory.API8)


def to_markdown(faelle: list[TestCase], lang: Lang = "de", *, title: str = "") -> str:
    t = _Texte(lang)
    z = [f"# {t('Prüfsatz', 'Test catalogue')}: {title}" if title else f"# {t('Prüfsatz', 'Test catalogue')}", ""]
    z.append(t(f"{len(faelle)} Testfälle. Ohne ausführbare Payloads — sicheres Sollverhalten zuerst.",
               f"{len(faelle)} test cases. No executable payloads — safe expected behaviour first."))
    z.append("")
    for c in faelle:
        z.append(f"## [P{c.priority}] {c.title}")
        z.append(f"**{t('Operation', 'Operation')}:** `{c.operation}`  ")
        if c.also_applies_to:
            z.append(f"**{t('Gilt auch für', 'Also applies to')}:** " + ", ".join(f"`{a}`" for a in c.also_applies_to) + "  ")
        z.append(f"**{t('Kategorie', 'Category')}:** {', '.join(c.controls)}  ")
        z.append(f"**{t('Statisch', 'Static')}:** {c.static_state.value}" + (f" ({c.related_check})" if c.related_check else "") + "  ")
        z.append("")
        z.append(f"**{t('Vorbedingung', 'Precondition')}:** {c.precondition}")
        z.append("")
        for i, s in enumerate(c.steps, 1):
            z.append(f"{i}. {s}")
        z.append("")
        z.append(f"**{t('Erwartet', 'Expected')}:** {c.expected}  ")
        z.append(f"**{t('Befund, wenn', 'Finding if')}:** {c.fail_signal}")
        z.append("")
    return "\n".join(z)
