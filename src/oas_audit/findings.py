"""Gemeinsames Befund-Modell für die statische Analyse.

Ein Befund aus einem Dokument ist keine Messung. Deshalb trägt jeder Befund
seinen Sicherheitsgrad (:class:`Confidence`) und wird nie als „verifiziert"
ausgegeben — das bleibt einem Werkzeug vorbehalten, das die Schnittstelle
tatsächlich anspricht.

Dieses Modell teilen sich alle statischen Analysen: die der OpenAPI-Spezifikation
und die der Gateway-Konfiguration.
"""

from __future__ import annotations

import enum
import hashlib

from pydantic import BaseModel, Field

from oas_audit.models import OWASPCategory, Severity


class Confidence(str, enum.Enum):
    """Wie belastbar ist die Aussage?"""

    #: Direkt aus dem Dokument ablesbar. Fließt in die Bewertung ein.
    BELEGT = "belegt"
    #: Starkes Indiz, aber nicht abschließend entscheidbar. Hinweis, kein Urteil.
    WAHRSCHEINLICH = "wahrscheinlich"
    #: Nur im laufenden Betrieb prüfbar. Wird gezählt und benannt, nie bewertet.
    LAUFZEIT = "laufzeit"


class Scope(str, enum.Enum):
    DOKUMENT = "dokument"
    ENDPUNKT = "endpunkt"
    API = "api"


class Evidence(BaseModel):
    """Der Beleg im Quelldokument — ohne ihn ist ein Befund eine Behauptung."""

    pointer: str  # JSON-Pointer oder Asset-Pfad, z.B. "#/paths/~1orders/post/security"
    excerpt: str = ""  # max. 200 Zeichen, nur Struktur/Feldnamen — nie Beispielwerte
    note: str = ""

    def truncated(self) -> Evidence:
        return self if len(self.excerpt) <= 200 else self.model_copy(
            update={"excerpt": self.excerpt[:197] + "..."}
        )


class Finding(BaseModel):
    """Ein statischer Befund."""

    check_id: str  # z.B. "gw.no_identify_policy"
    title: str
    confidence: Confidence
    severity: Severity
    owasp: OWASPCategory | None = None

    scope: Scope = Scope.DOKUMENT
    subject: str = ""  # API-Name, Pfad oder Asset — worauf sich der Befund bezieht
    method: str | None = None

    reason: str = ""  # Klartext: warum greift die Regel hier?
    remediation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)

    #: Aggregierte Befunde melden eine Gesamtzahl statt N Einzelbefunde. Eine
    #: Regel, die bei über der Hälfte aller Objekte anschlägt, beschreibt einen
    #: Stil und keine Schwachstelle — als Einzelbefund wäre sie nur Rauschen.
    aggregate_count: int | None = None
    #: Bei Aggregaten: die betroffenen Subjekte (Pfade, APIs), damit der Bericht
    #: sie auflisten kann und die Abdeckung messbar bleibt.
    affected: list[str] = Field(default_factory=list)

    #: Welche Note der Befund beeinflusst: "design" (Sicherheitsdesign) oder
    #: "hygiene" (Spezifikationshygiene). Getrennt, damit saubere Schemata eine
    #: fehlende Authentifizierung nicht wegmitteln können.
    dimension: str = "design"
    #: Deckelt die Note der Dimension auf diesen Buchstaben (z.B. "D"), solange
    #: der Befund besteht. Wird im Bericht mit Begründung ausgewiesen.
    cap: str | None = None

    @property
    def scores(self) -> bool:
        """Nur belegte Befunde wirken auf die Bewertung.

        Ein belegtes Aggregat zählt dabei einmal — dreißig unauthentifizierte
        Operationen sind ein Befund, aber kein harmloser. Hinweise (wahrscheinlich)
        bewerten nie, ob einzeln oder gesammelt.
        """
        return self.confidence is Confidence.BELEGT

    @property
    def id(self) -> str:
        """Stabile Kennung — gleiche Eingabe ergibt gleiche Kennung."""
        raw = f"{self.check_id}|{self.method or ''}|{self.subject}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class RuntimeGap(BaseModel):
    """Eine Prüfung, die statisch prinzipiell nicht entscheidbar ist.

    Wird im Bericht namentlich ausgewiesen und gezählt, nie bewertet. Das ist
    die Kennzahl neben der Note: was dieses Verfahren strukturell nicht sieht.
    """

    key: str
    title: str
    owasp: OWASPCategory | None = None
    why: str = ""


class BlindSpot(BaseModel):
    """Eine Struktur im Dokument, die diese Analyse nicht ausgewertet hat.

    Ein Werkzeug, das sagt, was es nicht gesehen hat, ist praktisch unangreifbar.
    Ein Werkzeug, das über eine ungelesene Operation „geprüft" meldet, ist es nie.
    """

    pointer: str
    what: str
    why: str = ""


#: Ab diesem Anteil betroffener Subjekte wird eine Regel aggregiert gemeldet.
AGGREGAT_SCHWELLE = 0.5

_RANG = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
         Severity.LOW: 3, Severity.INFO: 4}


def aggregate(
    findings: list[Finding],
    *,
    gesamt: int,
    immer: frozenset[str] | set[str] = frozenset(),
    schwelle: float = AGGREGAT_SCHWELLE,
) -> list[Finding]:
    """Dedupliziert, fasst allgegenwärtige Befunde zusammen und sortiert.

    ``gesamt`` ist die Zahl der Subjekte, auf die sich der Anteil bezieht
    (Endpunkte oder APIs). Regeln in ``immer`` werden unabhängig vom Anteil
    aggregiert — sie sind als Stil-Beobachtung konzipiert, nie als Einzelbefund.
    Dokument-weite Befunde (:attr:`Scope.DOKUMENT`) werden nie aggregiert.
    """
    gesehen: set[str] = set()
    eindeutig: list[Finding] = []
    for f in findings:
        if f.id in gesehen:
            continue
        gesehen.add(f.id)
        eindeutig.append(f)

    gesamt = gesamt or 1
    betroffen: dict[str, list[str]] = {}
    for f in eindeutig:
        liste = betroffen.setdefault(f.check_id, [])
        if f.subject not in liste:
            liste.append(f.subject)

    ergebnis: list[Finding] = []
    aggregiert: set[str] = set()
    for f in eindeutig:
        n = len(betroffen[f.check_id])
        zusammenfassen = f.check_id in immer or (
            f.scope is not Scope.DOKUMENT and n / gesamt > schwelle
        )
        if not zusammenfassen:
            ergebnis.append(f)
            continue
        if f.check_id in aggregiert:
            continue
        aggregiert.add(f.check_id)
        einheit = "APIs" if f.scope is Scope.API else "Endpunkten"
        # Ein belegter Befund bleibt belegt, auch wenn er überall zutrifft — nur
        # ein Hinweis wird als Gewohnheit eingestuft und zur Information.
        bleibt = f.confidence is Confidence.BELEGT
        ergebnis.append(f.model_copy(update={
            "scope": Scope.DOKUMENT,
            "subject": f"{n} von {gesamt} {einheit}",
            "method": None,
            "aggregate_count": n,
            "affected": sorted(betroffen[f.check_id]),
            "severity": f.severity if bleibt else Severity.INFO,
            "cap": f.cap if bleibt else None,
            "title": f.title + " (durchgängig)" if f.check_id not in immer else f.title,
            "reason": (
                f"Betrifft {n} von {gesamt} {einheit}. Ein Merkmal, das nahezu überall "
                "auftritt, beschreibt eine Gewohnheit und wird deshalb gesammelt gemeldet "
                "statt je Endpunkt einzeln. " + f.reason
            ) if f.check_id not in immer else f"Betrifft {n} von {gesamt} {einheit}. " + f.reason,
            "evidence": [],
        }))

    return sorted(ergebnis, key=lambda f: (_RANG[f.severity], f.check_id, f.subject))
