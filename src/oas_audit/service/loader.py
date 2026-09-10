"""Spezifikation aus nicht vertrauenswürdigen Bytes laden — ohne Dateisystem, ohne Netz.

Bewusst kein Aufruf von :func:`oas_audit.parser.openapi.load_spec`: dessen
Datei-Fallback (``Path(source).read_text()``) darf mit Nutzereingaben nie in
Berührung kommen.
"""

from __future__ import annotations

import json
from typing import Any

import jsonref
import yaml


class SpecError(ValueError):
    """Nutzerfehler: das Dokument ist nicht lesbar. Meldung ist für den Nutzer bestimmt."""


#: Mehr Alias-Verweise als das deutet auf eine Alias-Bombe hin — kein echtes
#: Dokument braucht sie. Wird vor dem Aufbau des Objektbaums gezählt.
MAX_YAML_ALIASES = 200
MAX_DEPTH = 200


#: Mehr Knoten als das nach vollständiger Alias-Expansion — abgelehnt, bevor
#: PyYAML den Baum aufbaut. Ein echtes Dokument mit 2 MB hat weit weniger.
MAX_EXPANDED_NODES = 2_000_000


def _yaml_bombe_pruefen(text: str) -> None:
    """Zählt Aliase und die *expandierte* Größe auf dem Knotengraphen.

    ``yaml.compose`` baut nur den Graphen mit geteilten Anker-Knoten — das ist
    billig. Erst ``safe_load`` würde jeden Alias kopieren; genau das darf bei
    einer Bombe nie passieren.
    """
    try:
        aliase = sum(1 for ev in yaml.parse(text) if isinstance(ev, yaml.AliasEvent))
        if aliase > MAX_YAML_ALIASES:
            raise SpecError("Zu viele YAML-Aliase — das Dokument wird nicht verarbeitet.")
        if aliase == 0:
            return
        wurzel = yaml.compose(text)
    except yaml.YAMLError:
        return  # der eigentliche Parse-Fehler wird in _yaml gemeldet
    except RecursionError as exc:
        raise SpecError("Dokument zu tief verschachtelt.") from exc
    groesse: dict[int, int] = {}

    def _size(node) -> int:
        k = id(node)
        if k in groesse:
            return groesse[k]
        if isinstance(node, yaml.SequenceNode):
            n = 1 + sum(_size(c) for c in node.value)
        elif isinstance(node, yaml.MappingNode):
            n = 1 + sum(_size(kn) + _size(vn) for kn, vn in node.value)
        else:
            n = 1
        groesse[k] = n
        if n > MAX_EXPANDED_NODES:
            raise SpecError("YAML-Aliase expandieren zu einem zu großen Dokument — abgelehnt.")
        return n

    try:
        _size(wurzel)
    except RecursionError as exc:
        raise SpecError("Dokument zu tief verschachtelt.") from exc


def _depth(obj: Any, limit: int = MAX_DEPTH) -> int:
    """Iterativ, damit die Tiefenprüfung selbst nicht am Rekursionslimit scheitert."""
    stapel = [(obj, 1)]
    maximal = 0
    while stapel:
        o, t = stapel.pop()
        if t > limit:
            return t
        maximal = max(maximal, t)
        if isinstance(o, dict):
            stapel.extend((v, t + 1) for v in o.values())
        elif isinstance(o, list):
            stapel.extend((v, t + 1) for v in o)
    return maximal


def load_spec_untrusted(data: bytes, *, hint: str = "") -> dict[str, Any]:
    """Bytes → aufgelöstes Dokument. Wirft :class:`SpecError` mit nutzbarer Meldung."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError("Dokument ist kein UTF-8-Text.") from exc
    text = text.strip()
    if not text:
        raise SpecError("Dokument ist leer.")

    hint = hint.lower()
    ist_json = text.startswith(("{", "[")) or hint.endswith(".json") or "json" in hint
    try:
        if ist_json:
            try:
                raw = json.loads(text)
            except json.JSONDecodeError as exc:
                if hint.endswith(".json") or "json" in hint:
                    raise SpecError(f"Kein gültiges JSON: {exc.msg} (Zeile {exc.lineno}).") from exc
                raw = _yaml(text)
        else:
            raw = _yaml(text)
    except RecursionError as exc:
        raise SpecError("Dokument zu tief verschachtelt.") from exc

    if not isinstance(raw, dict):
        raise SpecError("Dokument ist kein Objekt auf oberster Ebene — erwartet wird eine OpenAPI- oder Swagger-Spezifikation.")
    if _depth(raw) > MAX_DEPTH:
        raise SpecError(f"Dokument zu tief verschachtelt (mehr als {MAX_DEPTH} Ebenen).")
    if not ("openapi" in raw or "swagger" in raw):
        raise SpecError("Weder ein openapi- noch ein swagger-Feld gefunden — ist das eine API-Spezifikation?")

    try:
        return jsonref.replace_refs(raw, lazy_load=False)
    except RecursionError as exc:
        raise SpecError("Referenzen zu tief verschachtelt.") from exc
    except jsonref.JsonRefError as exc:
        raise SpecError(f"Nicht auflösbare Referenz: {exc}") from exc


def _yaml(text: str) -> Any:
    _yaml_bombe_pruefen(text)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        wo = f" (Zeile {mark.line + 1})" if mark else ""
        raise SpecError(f"Kein gültiges YAML{wo}.") from exc
