"""Zwei Schulnoten mit Cap-Regeln — kein Prozentwert.

Ein heuristisches Urteil aus einem Dokument darf keine Prozentpunkt-Genauigkeit
behaupten. Deshalb Buchstaben, und deshalb zwei getrennte Noten:

* **Sicherheitsdesign** — Authentifizierung, Autorisierung, Offenlegung.
* **Spezifikationshygiene** — Vollständigkeit und Konsistenz des Dokuments.

Getrennt, damit saubere Schemata eine fehlende Authentifizierung nicht
wegmitteln können. Und mit Deckeln nach dem Vorbild von SSL Labs: eine
dokumentierte Offenlegung sensibler Daten ohne Authentifizierung begrenzt die
Note auf F — egal, wie gut der Rest aussieht. Jeder Deckel wird mit Begründung
ausgewiesen.

Das Subjekt der Note ist die *Spezifikation*, nicht die API: „Spezifikations-
Reifegrad D“ ist eine Aussage über das Dokument. Eine gute Note bedeutet, dass
die Spezifikation testreif ist — nicht, dass die Schnittstelle sicher ist.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from oas_audit.audit import AuditResult
from oas_audit.findings import Finding
from oas_audit.models import Severity

NOTEN = ["A", "B", "C", "D", "F"]

PUNKTE = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

#: Obergrenzen (einschließlich) je Note. Alles darüber ist F.
SCHWELLEN = [("A", 0), ("B", 10), ("C", 30), ("D", 60)]

TESTREIFE_SATZ = (
    "Eine gute Note bedeutet, dass die Spezifikation testreif ist — "
    "nicht, dass die Schnittstelle sicher ist."
)


class Cap(BaseModel):
    check_id: str
    subject: str
    cap: str
    reason: str


class Grade(BaseModel):
    dimension: str
    letter: str
    points: int
    #: Note allein aus den Punkten, vor Anwendung der Deckel.
    uncapped: str
    caps: list[Cap] = Field(default_factory=list)
    finding_count: int = 0

    @property
    def capped(self) -> bool:
        return self.letter != self.uncapped


class Score(BaseModel):
    design: Grade
    hygiene: Grade
    #: Wie viele Risikoklassen dieses Verfahren strukturell nicht beurteilen kann.
    runtime_gap_count: int
    note: str = TESTREIFE_SATZ


def note_aus_punkten(punkte: int) -> str:
    for note, grenze in SCHWELLEN:
        if punkte <= grenze:
            return note
    return "F"


def _schlechter(a: str, b: str) -> str:
    return a if NOTEN.index(a) >= NOTEN.index(b) else b


def _bewerte(dimension: str, findings: list[Finding]) -> Grade:
    relevant = [f for f in findings if f.dimension == dimension and f.scores]
    punkte = sum(PUNKTE[f.severity] for f in relevant)
    uncapped = note_aus_punkten(punkte)
    caps = [
        Cap(check_id=f.check_id, subject=f.subject, cap=f.cap, reason=f.title)
        for f in relevant if f.cap
    ]
    letter = uncapped
    for c in caps:
        letter = _schlechter(letter, c.cap)
    return Grade(dimension=dimension, letter=letter, points=punkte, uncapped=uncapped,
                 caps=caps, finding_count=len(relevant))


def score(result: AuditResult) -> Score:
    return Score(
        design=_bewerte("design", result.findings),
        hygiene=_bewerte("hygiene", result.findings),
        runtime_gap_count=len(result.runtime_gaps),
    )
