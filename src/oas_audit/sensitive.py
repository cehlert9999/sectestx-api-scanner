"""Erkennung sensibler Felder in Schemata — nur über Feldnamen, nie über Werte.

Beispielwerte (``example``, ``default``) werden bewusst nicht gelesen: in freier
Wildbahn enthalten sie erstaunlich oft echte Tokens und Kundendaten, und ein
Bericht darf nichts weiterverbreiten, was im Dokument versehentlich steht.

Der Abgleich arbeitet auf *Tokens*, nicht auf Teilzeichenketten: ``bic`` soll
``swift_bic`` treffen, aber nicht ``public``; ``card_number`` soll
``creditCardNumber`` treffen, aber ``number`` allein nichts auslösen.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterator
from typing import Any


class Kategorie(str, enum.Enum):
    FINANZ = "finanz"  # Zahlungs- und Steuerdaten — der stärkste Hebel für Betrug
    CREDENTIAL = "credential"  # Geheimnisse, die nie in einer Antwort stehen dürfen
    PII = "pii"  # personenbezogene Daten im engeren Sinn


# Token-Folgen. Eine Folge trifft, wenn sie zusammenhängend im Feldnamen vorkommt.
_MUSTER: dict[Kategorie, tuple[tuple[str, ...], ...]] = {
    Kategorie.FINANZ: (
        ("iban",), ("bic",), ("swift",), ("kontonummer",), ("blz",),
        ("account", "number"), ("account", "no"), ("bank", "account"),
        ("credit", "card"), ("creditcard",), ("card", "number"), ("cardnumber",),
        ("cvv",), ("cvc",),
        ("ssn",), ("social", "security"), ("sozialversicherungsnummer",),
        ("tax", "id"), ("taxid",), ("vat", "id"), ("vatid",), ("steuer", "id"),
        ("steuernummer",), ("ust", "id"),
        ("passport",), ("reisepass",), ("national", "id"), ("personalausweis",),
    ),
    Kategorie.CREDENTIAL: (
        ("password",), ("passwd",), ("pwd",), ("passwort",), ("kennwort",),
        ("secret",), ("private", "key"), ("privatekey",),
        ("api", "key"), ("apikey",), ("access", "key"),
        ("token",), ("session", "id"), ("sessionid",), ("otp",),
        ("security", "answer"), ("recovery", "code"),
    ),
    Kategorie.PII: (
        ("email",), ("e", "mail"), ("phone",), ("mobile",), ("telefon",), ("handy",),
        ("date", "of", "birth"), ("birth", "date"), ("birthdate",), ("birthday",),
        ("dob",), ("geburtsdatum",),
        ("salary",), ("gehalt",), ("income",), ("einkommen",),
        ("credit", "score"), ("bonitaet",), ("schufa",),
        ("internal", "note"), ("internal", "notes"), ("internal", "comment"),
        ("religion",), ("ethnicity",), ("gender",), ("nationality",),
        ("street",), ("strasse",), ("home", "address"),
    ),
}

_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

# Felder, die in einer Login-/Token-Antwort *sollen* — kein Befund.
AUTH_FLOW_FELDER = {("token",), ("access", "key")}


def tokens(name: str) -> list[str]:
    """``creditCardNumber`` → ``['credit', 'card', 'number']``, ``vat_id`` → ``['vat', 'id']``."""
    out: list[str] = []
    for teil in re.split(r"[^A-Za-z0-9]+", name):
        out.extend(t.lower() for t in _TOKEN_RE.findall(teil))
    return out


def _enthaelt(folge: tuple[str, ...], toks: list[str]) -> bool:
    n = len(folge)
    return any(tuple(toks[i:i + n]) == folge for i in range(len(toks) - n + 1))


def kategorien(feldname: str, *, auth_flow: bool = False) -> set[Kategorie]:
    """Welche Kategorien treffen auf diesen Feldnamen zu?"""
    toks = tokens(feldname)
    if not toks:
        return set()
    treffer: set[Kategorie] = set()
    for kat, muster in _MUSTER.items():
        for folge in muster:
            if auth_flow and kat is Kategorie.CREDENTIAL and folge in AUTH_FLOW_FELDER:
                continue
            if _enthaelt(folge, toks):
                treffer.add(kat)
                break
    return treffer


def feldnamen(schema: Any, *, max_tiefe: int = 12) -> Iterator[str]:
    """Alle Property-Namen eines Schemas, rekursiv, zyklensicher.

    ``$ref`` sind zu diesem Zeitpunkt bereits aufgelöst; ein rekursives Schema
    erscheint deshalb als Zyklus im Objektgraphen und wird über die Identität
    des zugrunde liegenden Objekts erkannt.
    """
    gesehen: set[int] = set()

    def _walk(s: Any, tiefe: int) -> Iterator[str]:
        if not isinstance(s, dict) or tiefe > max_tiefe:
            return
        kern = getattr(s, "__subject__", s)
        if id(kern) in gesehen:
            return
        gesehen.add(id(kern))
        for name, sub in (s.get("properties") or {}).items():
            yield str(name)
            yield from _walk(sub, tiefe + 1)
        for key in ("items", "additionalProperties", "not"):
            yield from _walk(s.get(key), tiefe + 1)
        for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
            for sub in s.get(key) or []:
                yield from _walk(sub, tiefe + 1)

    yield from _walk(schema, 0)


def sensible_felder(schema: Any, *, auth_flow: bool = False) -> dict[Kategorie, list[str]]:
    """Sensible Feldnamen eines Schemas, nach Kategorie gruppiert, dedupliziert."""
    out: dict[Kategorie, list[str]] = {}
    for name in feldnamen(schema):
        for kat in kategorien(name, auth_flow=auth_flow):
            liste = out.setdefault(kat, [])
            if name not in liste:
                liste.append(name)
    return out


def schemata(schema: Any, *, max_tiefe: int = 12) -> Iterator[tuple[str, dict[str, Any]]]:
    """Alle (Pfad, Teilschema)-Paare — für Constraint-Prüfungen."""
    gesehen: set[int] = set()

    def _walk(s: Any, pfad: str, tiefe: int) -> Iterator[tuple[str, dict[str, Any]]]:
        if not isinstance(s, dict) or tiefe > max_tiefe:
            return
        kern = getattr(s, "__subject__", s)
        if id(kern) in gesehen:
            return
        gesehen.add(id(kern))
        yield pfad, s
        for name, sub in (s.get("properties") or {}).items():
            yield from _walk(sub, f"{pfad}/properties/{name}", tiefe + 1)
        for key in ("items", "additionalProperties"):
            if isinstance(s.get(key), dict):
                yield from _walk(s[key], f"{pfad}/{key}", tiefe + 1)
        for key in ("allOf", "anyOf", "oneOf"):
            for i, sub in enumerate(s.get(key) or []):
                yield from _walk(sub, f"{pfad}/{key}/{i}", tiefe + 1)

    yield from _walk(schema, "", 0)
