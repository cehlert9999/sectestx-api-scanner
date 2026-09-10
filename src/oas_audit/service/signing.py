"""HMAC-Signatur über das Ergebnis — der Bericht wird erst später erzeugt.

Der Scan ist zustandslos: das Ergebnis geht signiert an den Browser zurück.
Fordert der Nutzer daraus einen Bericht an, prüft die Signatur, dass das
Ergebnis unverändert vom Dienst stammt — ohne dass je etwas gespeichert wurde.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(payload: dict[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical(payload), hashlib.sha256).hexdigest()


def verify(payload: dict[str, Any], signature: str, secret: str) -> bool:
    return hmac.compare_digest(sign(payload, secret), str(signature or ""))
