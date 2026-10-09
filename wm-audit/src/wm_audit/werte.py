"""Lesart für JSON-Werte aus einem Gateway-Export.

Ein Export kommt aus Gateway-Versionen, die einzelne Felder unterschiedlich
serialisieren: ein Wahrheitswert steht mal als ``true``, mal als ``"true"``,
eine Version mal als ``"1.0"``, mal als Zahl. Diese Datei legt **eine** Lesart
fest, damit aus einem Feld nie stillschweigend das Gegenteil wird — ``bool("false")``
ist in Python ``True``.

Die Rust-Portierung (``code/wm-audit-rs``) implementiert exakt dieselben Regeln;
die Golden-Files unter ``tests/golden`` sichern das ab. Wer hier etwas ändert,
ändert es dort mit.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

#: Ganzzahlen außerhalb dieses Bereichs werden wie in ``serde_json`` als
#: Gleitkommazahl gelesen — sonst wären die beiden Implementierungen nicht gleich.
_INT_MIN = -(2**63)
_INT_MAX = 2**64 - 1

_GANZZAHL = re.compile(r"[+-]?[0-9]+")
_STRUKTUR = re.compile(r'["\\\[\]{}]')


def text(v: Any) -> str:
    """Text eines Skalars. Listen, Objekte und ``null`` ergeben ``""``."""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    return ""


def text_oder_none(v: Any) -> str | None:
    """Wie :func:`text`, aber ein fehlendes oder ``null``-Feld bleibt ``None``."""
    return None if v is None else text(v)


def wahrheitswert(v: Any, standard: bool) -> bool:
    """``true``/``false`` als JSON-Wert oder als Text (Groß-/Kleinschreibung egal)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        klein = v.lower()
        if klein == "true":
            return True
        if klein == "false":
            return False
    return standard


def ganzzahl(v: Any) -> int:
    """Ganzzahl aus Zahl oder Ziffern-Text; alles andere ergibt ``0``."""
    if isinstance(v, bool):
        n = 0
    elif isinstance(v, int):
        n = v
    elif isinstance(v, float):
        n = int(v)
    elif isinstance(v, str) and _GANZZAHL.fullmatch(v) and len(v) <= 40:
        n = int(v)  # längere Ziffernfolgen liegen ohnehin außerhalb von i64
    else:
        n = 0
    return n if -(2**63) <= n < 2**63 else 0


def text_liste(v: Any) -> list[str]:
    """Liste → Text je Element; ein einzelner Skalar → einelementige Liste."""
    if isinstance(v, list):
        return [text(x) for x in v]
    if v is None or isinstance(v, dict):
        return []
    return [text(v)]


def objekte(v: Any) -> list[dict[str, Any]]:
    """Nur die JSON-Objekte einer Liste; alles andere wird ignoriert."""
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def lokalisiert(v: Any) -> str:
    """``[{"value": "...", "locale": "en"}]`` → erster Wert."""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return text(v[0].get("value"))
    return ""


# ------------------------------------------------------------- JSON-Einlesen


class JsonFehler(ValueError):
    """Die Datei ist kein JSON im Sinne dieser Lesart."""


def verschachtelung(quelle: str) -> int:
    """Maximale Verschachtelungstiefe von Arrays/Objekten, Strings ausgenommen.

    Läuft **vor** dem Parser, damit eine Tiefenbombe nie den Rekursionsstapel
    erreicht. Arbeitet auf ungültigem JSON genauso wie die Rust-Variante.
    """
    tiefe = maximum = 0
    im_string = False
    ueberspringen = -1
    for m in _STRUKTUR.finditer(quelle):
        i = m.start()
        z = quelle[i]
        if im_string:
            if i == ueberspringen:
                continue
            if z == "\\":
                ueberspringen = i + 1
            elif z == '"':
                im_string = False
        elif z == '"':
            im_string = True
        elif z in "[{":
            tiefe += 1
            maximum = max(maximum, tiefe)
        elif z in "]}":
            tiefe -= 1
    return maximum


def _ganzzahl_oder_float(s: str) -> int | float:
    if s == "-0":
        return -0.0  # serde_json liest "-0" als Gleitkommazahl mit Vorzeichen
    n = int(s)
    return n if _INT_MIN <= n <= _INT_MAX else _endlich(s)


def _endlich(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):
        raise JsonFehler("Zahl außerhalb des darstellbaren Bereichs")
    return f


def _konstante(s: str) -> Any:
    raise JsonFehler(f"{s} ist kein JSON")


def _pruefe_strings(wert: Any) -> None:
    """Ungepaarte Surrogate (``"\\ud800"``) lehnt auch ``serde_json`` ab."""
    stapel = [wert]
    while stapel:
        w = stapel.pop()
        if isinstance(w, str):
            w.encode("utf-8")
        elif isinstance(w, list):
            stapel.extend(w)
        elif isinstance(w, dict):
            for k, x in w.items():
                k.encode("utf-8")
                stapel.append(x)


def lade_json(quelle: str) -> Any:
    """Striktes JSON: kein ``NaN``/``Infinity``, nur endliche Zahlen, gültiges Unicode."""
    try:
        wert = json.loads(
            quelle,
            parse_int=_ganzzahl_oder_float,
            parse_float=_endlich,
            parse_constant=_konstante,
        )
        _pruefe_strings(wert)
    except (ValueError, UnicodeEncodeError) as e:
        raise JsonFehler(str(e)) from e
    return wert
