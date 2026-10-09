"""Einlesen eines webMethods-API-Gateway-Exports.

Die Struktur eines Exports (Verzeichnis oder ZIP):

    assets/
      API/API.<uuid>/
        API.<uuid>                       ← die API selbst, inkl. apiDefinition
        Policy/Policy.<uuid>/
          Policy.<uuid>                  ← Zuordnung Stage → PolicyAction
          PolicyAction/PolicyAction.<uuid>
      Application/  Alias/  PassmanData/

Die Asset-Dateien tragen keine Dateiendung; erkannt werden sie am Namen:

* **API-Datei** — ``API.<x>`` in einem Verzeichnis, das ebenfalls ``API.<x>`` heißt.
* **Policy** — ``Policy.<x>`` in einem Verzeichnis ``Policy.<x>`` unterhalb einer
  API. Ihre ``policyEnforcements`` legen fest, welche Aktionen wirklich greifen.
* **Policy-Aktion** — ``PolicyAction.<x>`` irgendwo unterhalb eines ``API.*``-
  Verzeichnisses; sie gehört zum innersten davon.
* **Alias** — ``Alias.<x>`` in einem Verzeichnis ``Alias``. Einfache Aliase
  (``type: simple``) lösen Routing-Ziele wie ``${Backend_Alias}`` auf; sie gelten
  für alle APIs unterhalb des Verzeichnisses, das den ``Alias``-Ordner enthält.

Hat eine API eine Policy mit ``policyEnforcements``, zählen nur die dort
referenzierten Aktionen. Eine Aktion, die als Datei vorliegt, aber keiner Stage
zugeordnet ist, greift im Gateway nicht — sie wird als ``nicht_zugeordnet``
übersprungen und kann keine Lücke verdecken. Ohne solche Policy zählen alle
Aktionen (Verhalten älterer Exporte und konstruierter Fixtures).

Jede API ist über ihren **Verzeichnispfad** eindeutig, nicht über ihre UUID.
Ein Archiv mit mehreren Exporten derselben API (etwa ``test/`` und ``prod/``)
ergibt deshalb mehrere APIs, und eine Policy aus ``prod`` verdeckt nie eine
Lücke in ``test``. ZIP und Verzeichnis werden mit derselben Logik gelesen und
liefern bei gleichem Inhalt dasselbe Ergebnis.

Der Reader ist nachsichtig: eine unlesbare Datei wird übersprungen, nicht zum
Abbruch erhoben — aber sie wird im Export unter ``uebersprungen`` vermerkt.
Abgebrochen wird nur, wenn das Archiv als Ganzes nicht lesbar ist oder eine
Grenze für das ganze Archiv überschritten wird (:class:`ExportFehler`).

Sicherheitshinweis: Exporte enthalten unter ``PassmanData`` Zugangsdaten und
unter ``Keystore`` Schlüsselmaterial. Einträge, in deren Pfad ein gesperrter
Name vorkommt, werden **nie geöffnet** — weder dekomprimiert noch gelesen,
nur gezählt. Was nicht im Speicher landet, kann auch nicht in einem Bericht
auftauchen.

Die Rust-Portierung (``code/wm-audit-rs``) implementiert dieselben Regeln.
"""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wm_audit import werte
from wm_audit.models import (
    GatewayApi,
    GatewayExport,
    NativeEndpoint,
    PolicyAction,
    Uebersprungen,
)

#: Assets, die niemals geöffnet werden — sie enthalten Geheimnisse. Gesperrt ist
#: jede Pfadkomponente, die so heißt oder mit ``<Name>.`` beginnt (ohne Rücksicht
#: auf Groß-/Kleinschreibung).
GESPERRTE_ASSETS = ("PassmanData", "Keystore", "Truststore", "Kerberos")

_GESPERRT_KLEIN = tuple(s.lower() for s in GESPERRTE_ASSETS)


@dataclass(frozen=True)
class Grenzen:
    """Obergrenzen gegen ZIP- und JSON-Bomben."""

    #: Einträge im ZIP-Verzeichnis bzw. reguläre Dateien im Verzeichnisbaum.
    eintraege: int = 50_000
    #: Bytes je Asset-Datei (nach dem Entpacken).
    datei: int = 32 * 1024 * 1024
    #: Gelesene Bytes über alle Asset-Dateien zusammen.
    gesamt: int = 512 * 1024 * 1024
    #: Verschachtelungstiefe von JSON-Arrays/-Objekten.
    tiefe: int = 100


STANDARD_GRENZEN = Grenzen()


class ExportFehler(Exception):
    """Der Export ist als Ganzes nicht lesbar."""


class _Uebersprungen(Exception):
    def __init__(self, grund: str) -> None:
        super().__init__(grund)
        self.grund = grund


# ------------------------------------------------------------------ Pfade


def _teile(name: str) -> list[str]:
    """``assets\\API/./API.x/`` → ``["assets", "API", "API.x"]``."""
    return [t for t in name.replace("\\", "/").split("/") if t not in ("", ".")]


def ist_gesperrt(teile: list[str]) -> bool:
    for t in teile:
        k = t.lower()
        if any(k == s or k.startswith(s + ".") for s in _GESPERRT_KLEIN):
            return True
    return False


@dataclass(frozen=True)
class _Art:
    art: str  # "api", "policy", "aktion" oder "alias"
    #: Bei api/policy/aktion der Verzeichnispfad der API (eindeutig im Export),
    #: bei alias das Verzeichnis, das den ``Alias``-Ordner enthält.
    schluessel: str


def _innerste_api(teile: list[str]) -> str | None:
    for i in range(len(teile) - 2, -1, -1):
        if teile[i].startswith("API."):
            return "/".join(teile[: i + 1])
    return None


def _einordnen(teile: list[str]) -> _Art | None:
    """API-Datei, Policy, Policy-Aktion, Alias oder uninteressant (``None``)."""
    if len(teile) < 2:
        return None
    name = teile[-1]
    if name.startswith("API.") and name == teile[-2]:
        return _Art("api", "/".join(teile[:-1]))
    if name.startswith("Policy.") and name == teile[-2]:
        api = _innerste_api(teile)
        return _Art("policy", api) if api is not None else None
    if name.startswith("PolicyAction."):
        api = _innerste_api(teile)
        return _Art("aktion", api) if api is not None else None
    if name.startswith("Alias.") and teile[-2] == "Alias":
        return _Art("alias", "/".join(teile[:-2]))
    return None


# ------------------------------------------------------------------ Aufbau


def _policy_action(raw: dict[str, Any]) -> PolicyAction:
    return PolicyAction(
        id=werte.text(raw.get("id")),
        name=werte.lokalisiert(raw.get("names")),
        template_key=werte.text(raw.get("templateKey")),
        parameters=werte.objekte(raw.get("parameters")),
        active_flag=werte.wahrheitswert(raw.get("active"), False),
    )


def _native_endpoints(raw: Any) -> list[NativeEndpoint]:
    eintraege = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    return [
        NativeEndpoint(
            uri=werte.text(e.get("uri")),
            pass_security_headers=werte.wahrheitswert(e.get("passSecurityHeaders"), False),
            connection_timeout=werte.ganzzahl(e.get("connectionTimeoutDuration")),
        )
        for e in eintraege
        if isinstance(e, dict)
    ]


def _zugeordnete_ids(raw: dict[str, Any]) -> set[str] | None:
    """IDs aller Aktionen in ``policyEnforcements``; ``None``, wenn das Feld fehlt."""
    stages = raw.get("policyEnforcements")
    if not isinstance(stages, list):
        return None
    return {
        werte.text(e.get("enforcementObjectId"))
        for stage in werte.objekte(stages)
        for e in werte.objekte(stage.get("enforcements"))
    }


def _build_api(
    raw: dict[str, Any],
    actions: list[PolicyAction],
    source: str,
    aliase: dict[str, str],
) -> GatewayApi:
    definition = raw.get("apiDefinition")
    gruppen = raw.get("apiGroups")
    return GatewayApi(
        id=werte.text(raw.get("id")),
        name=werte.text(raw.get("apiName")),
        version=werte.text_oder_none(raw.get("apiVersion")),
        type=werte.text(raw.get("type")),
        is_active=werte.wahrheitswert(raw.get("isActive"), True),
        maturity_state=werte.text(raw.get("maturityState")),
        api_groups=[werte.text(g) for g in gruppen] if isinstance(gruppen, list) else [],
        native_endpoints=_native_endpoints(raw.get("nativeEndpoint")),
        policy_actions=actions,
        api_definition=definition if isinstance(definition, dict) else None,
        source_path=source,
        aliase=aliase,
    )


def _dekodieren(daten: bytes, grenzen: Grenzen) -> dict[str, Any]:
    try:
        quelle = daten.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _Uebersprungen("kein_utf8") from e
    if werte.verschachtelung(quelle) > grenzen.tiefe:
        raise _Uebersprungen("zu_tief")
    try:
        wert = werte.lade_json(quelle)
    except werte.JsonFehler as e:
        raise _Uebersprungen("kein_json") from e
    if not isinstance(wert, dict):
        raise _Uebersprungen("kein_objekt")
    return wert


#: Ein Eintrag: Pfad im Export und ein Leser, der höchstens ``n`` Bytes liefert.
_Eintrag = tuple[str, Callable[[int], bytes]]


def _aufbauen(
    eintraege: Iterator[_Eintrag | None],
    grenzen: Grenzen,
    *,
    source: str,
    art: str,
    sha256: str | None,
) -> GatewayExport:
    """Gemeinsamer Kern für ZIP und Verzeichnis.

    ``None`` im Strom steht für einen gesperrten Eintrag, der nur gezählt wird.
    """
    api_raw: dict[str, tuple[str, dict[str, Any]]] = {}
    aktionen: dict[str, list[tuple[str, PolicyAction]]] = {}
    zuordnung: dict[str, set[str]] = {}
    alias_dateien: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    uebersprungen: list[Uebersprungen] = []
    gesperrt = 0
    gelesen = 0

    for eintrag in eintraege:
        if eintrag is None:
            gesperrt += 1
            continue
        pfad, lesen = eintrag
        teile = _teile(pfad)
        if ist_gesperrt(teile):
            gesperrt += 1
            continue
        einordnung = _einordnen(teile)
        if einordnung is None:
            continue
        pfad = "/".join(teile)
        try:
            daten = lesen(grenzen.datei + 1)
            gelesen += len(daten)
            if gelesen > grenzen.gesamt:
                raise ExportFehler(
                    f"Export überschreitet {grenzen.gesamt} Bytes entpackte Asset-Daten"
                )
            if len(daten) > grenzen.datei:
                raise _Uebersprungen("zu_gross")
            raw = _dekodieren(daten, grenzen)
            if einordnung.art == "api" and "apiName" not in raw:
                raise _Uebersprungen("ohne_apiname")
        except _Uebersprungen as u:
            uebersprungen.append(Uebersprungen(pfad=pfad, grund=u.grund))
            continue

        k = einordnung.schluessel
        if einordnung.art == "api":
            api_raw[k] = (pfad, raw)
        elif einordnung.art == "aktion":
            aktionen.setdefault(k, []).append((pfad, _policy_action(raw)))
        elif einordnung.art == "policy":
            ids = _zugeordnete_ids(raw)
            if ids is not None:
                zuordnung.setdefault(k, set()).update(ids)
        else:
            alias_dateien.setdefault(k, []).append((pfad, raw))

    aliase_je_wurzel = {w: _einfache_aliase(d) for w, d in alias_dateien.items()}

    apis = []
    for api_pfad in sorted(api_raw):
        datei_pfad, raw = api_raw[api_pfad]
        eigene = []
        for p, a in sorted(aktionen.get(api_pfad, []), key=lambda x: x[0]):
            if api_pfad in zuordnung and a.id not in zuordnung[api_pfad]:
                uebersprungen.append(Uebersprungen(pfad=p, grund="nicht_zugeordnet"))
            else:
                eigene.append(a)
        apis.append(_build_api(raw, eigene, datei_pfad, _aliase_fuer(api_pfad, aliase_je_wurzel)))
    for api_pfad, liste in aktionen.items():
        if api_pfad not in api_raw:
            uebersprungen.extend(Uebersprungen(pfad=p, grund="ohne_api") for p, _ in liste)

    return GatewayExport(
        apis=apis,
        source=source,
        art=art,
        sha256=sha256,
        uebersprungen=sorted(uebersprungen, key=lambda u: (u.pfad, u.grund)),
        gesperrt=gesperrt,
    )


def _einfache_aliase(dateien: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
    """Name → Wert aller ``simple``-Aliase; bei Namensgleichheit gewinnt der erste Pfad."""
    aliase: dict[str, str] = {}
    for _, raw in sorted(dateien, key=lambda x: x[0]):
        if werte.text(raw.get("type")) != "simple":
            continue
        name = werte.text(raw.get("name"))
        if name and name not in aliase:
            aliase[name] = werte.text(raw.get("value"))
    return aliase


def _aliase_fuer(api_pfad: str, je_wurzel: dict[str, dict[str, str]]) -> dict[str, str]:
    """Die Aliase der nächstgelegenen Wurzel oberhalb der API."""
    passend = [w for w in je_wurzel if w == "" or api_pfad.startswith(w + "/")]
    return dict(je_wurzel[max(passend, key=len)]) if passend else {}


# ------------------------------------------------------------------ Quellen


def _verzeichnis_eintraege(root: Path, grenzen: Grenzen) -> Iterator[_Eintrag | None]:
    """Reguläre Dateien unterhalb von ``root``; Symlinks werden nie verfolgt.

    In gesperrte Verzeichnisse wird nur hineingeschaut, um ihre Dateien zu
    zählen — geöffnet wird dort nichts.
    """
    anzahl = 0
    for ordner, verzeichnisse, dateien in os.walk(root, followlinks=False):
        verzeichnisse.sort()
        for name in sorted(dateien):
            voll = os.path.join(ordner, name)
            try:
                info = os.lstat(voll)
            except OSError:
                continue
            rel = os.path.relpath(voll, root).replace(os.sep, "/")
            try:
                rel.encode("utf-8")
            except UnicodeEncodeError:
                continue  # Dateiname ist kein gültiges UTF-8
            if stat.S_ISLNK(info.st_mode):
                yield rel, _symlink
                continue
            if not stat.S_ISREG(info.st_mode):
                continue  # FIFO, Gerät, Socket — Lesen könnte blockieren
            anzahl += 1
            if anzahl > grenzen.eintraege:
                raise ExportFehler(f"Export enthält mehr als {grenzen.eintraege} Dateien")
            yield rel, _datei_leser(voll)


def _symlink(_: int) -> bytes:
    raise _Uebersprungen("symlink")


def _datei_leser(pfad: str) -> Callable[[int], bytes]:
    def lesen(n: int) -> bytes:
        try:
            with open(pfad, "rb") as fh:
                return fh.read(n)
        except OSError as e:
            raise _Uebersprungen("lesefehler") from e

    return lesen


def read_directory(root: str | Path, grenzen: Grenzen = STANDARD_GRENZEN) -> GatewayExport:
    """Liest einen entpackten Export (oder ein ganzes Repository davon)."""
    root = Path(root).expanduser()
    if not root.is_dir():
        raise FileNotFoundError(f"Export nicht gefunden: {root}")
    return _aufbauen(
        _verzeichnis_eintraege(root, grenzen),
        grenzen,
        source=str(root),
        art="verzeichnis",
        sha256=None,
    )


_ERLAUBTE_KOMPRESSION = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


def _zip_eintraege(zf: zipfile.ZipFile) -> Iterator[_Eintrag | None]:
    for info in zf.infolist():
        if info.is_dir():
            continue
        if ist_gesperrt(_teile(info.filename)):
            yield None  # gezählt, nie dekomprimiert
            continue
        yield info.filename, _zip_leser(zf, info)


def _zip_leser(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> Callable[[int], bytes]:
    def lesen(n: int) -> bytes:
        if info.flag_bits & 0x1 or info.compress_type not in _ERLAUBTE_KOMPRESSION:
            raise _Uebersprungen("lesefehler")  # verschlüsselt oder exotisch komprimiert
        try:
            with zf.open(info) as fh:
                return fh.read(n)
        except (zipfile.BadZipFile, EOFError, OSError, RuntimeError,
                NotImplementedError, ValueError) as e:
            raise _Uebersprungen("lesefehler") from e

    return lesen


def read_zip(path: str | Path, grenzen: Grenzen = STANDARD_GRENZEN) -> GatewayExport:
    """Liest einen Export direkt aus dem ZIP, ohne ihn auf Platte zu entpacken."""
    path = Path(path).expanduser()
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            sha.update(block)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as e:
        raise ExportFehler(f"Keine gültige ZIP-Datei: {path}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > grenzen.eintraege:
            raise ExportFehler(f"ZIP enthält mehr als {grenzen.eintraege} Einträge")
        namen = [i.filename for i in infos]
        if len(set(namen)) != len(namen):
            raise ExportFehler("ZIP enthält doppelte Eintragsnamen")
        return _aufbauen(
            _zip_eintraege(zf),
            grenzen,
            source=str(path),
            art="zip",
            sha256=sha.hexdigest(),
        )


def read_export(path: str | Path, grenzen: Grenzen = STANDARD_GRENZEN) -> GatewayExport:
    """Liest einen Export — ZIP oder entpacktes Verzeichnis."""
    p = Path(path).expanduser()
    if p.is_dir():
        return read_directory(p, grenzen)
    if p.is_file():
        return read_zip(p, grenzen)
    raise FileNotFoundError(f"Export nicht gefunden: {p}")
