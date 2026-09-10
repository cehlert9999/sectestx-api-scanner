"""Einlesen eines webMethods-API-Gateway-Exports.

Die Struktur eines Exports (Verzeichnis oder ZIP):

    assets/
      API/API.<uuid>/
        API.<uuid>                       ← die API selbst, inkl. apiDefinition
        Policy/Policy.<uuid>/
          Policy.<uuid>                  ← Zuordnung Stage → PolicyAction
          PolicyAction/PolicyAction.<uuid>
      Application/  Alias/  PassmanData/

Die Asset-Dateien tragen keine Dateiendung; erkannt werden sie am Präfix des
Dateinamens. Der Reader ist bewusst nachsichtig: ein Export aus einer anderen
Gateway-Version darf einzelne Felder anders benennen, ohne dass das Einlesen
scheitert — eine unlesbare Datei wird übersprungen, nicht zum Abbruch erhoben.

Sicherheitshinweis: Exporte enthalten unter ``PassmanData`` Zugangsdaten und
unter ``Keystore`` Schlüsselmaterial. Beides wird hier bewusst **nicht**
eingelesen — was nicht im Speicher landet, kann auch nicht in einem Bericht
auftauchen.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from wm_audit.models import GatewayApi, GatewayExport, NativeEndpoint, PolicyAction

#: Assets, die niemals gelesen werden — sie enthalten Geheimnisse.
GESPERRTE_ASSETS = ("PassmanData", "Keystore", "Truststore", "Kerberos")


def _localized(entries: Any) -> str:
    """``[{"value": "...", "locale": "en"}]`` → erster Wert."""
    if isinstance(entries, list) and entries:
        first = entries[0]
        if isinstance(first, dict):
            return str(first.get("value", ""))
    return ""


def _policy_action(raw: dict[str, Any]) -> PolicyAction:
    return PolicyAction(
        id=str(raw.get("id", "")),
        name=_localized(raw.get("names")),
        template_key=str(raw.get("templateKey", "")),
        parameters=raw.get("parameters") or [],
        active_flag=bool(raw.get("active", False)),
    )


def _native_endpoints(raw: Any) -> list[NativeEndpoint]:
    entries = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        out.append(NativeEndpoint(
            uri=str(e.get("uri", "")),
            pass_security_headers=bool(e.get("passSecurityHeaders", False)),
            connection_timeout=int(e.get("connectionTimeoutDuration", 0) or 0),
        ))
    return out


def _build_api(raw: dict[str, Any], actions: list[PolicyAction], source: str) -> GatewayApi:
    return GatewayApi(
        id=str(raw.get("id", "")),
        name=str(raw.get("apiName", "")),
        version=raw.get("apiVersion"),
        type=str(raw.get("type", "")),
        is_active=bool(raw.get("isActive", True)),
        maturity_state=str(raw.get("maturityState", "")),
        api_groups=[str(g) for g in (raw.get("apiGroups") or [])],
        native_endpoints=_native_endpoints(raw.get("nativeEndpoint")),
        policy_actions=actions,
        api_definition=raw.get("apiDefinition"),
        source_path=source,
    )


def read_directory(root: str | Path) -> GatewayExport:
    """Liest einen entpackten Export (oder ein ganzes Repository davon)."""
    root = Path(root).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"Export nicht gefunden: {root}")

    apis: list[GatewayApi] = []
    for api_dir in sorted(root.rglob("API.*")):
        if not api_dir.is_dir():
            continue
        api_file = api_dir / api_dir.name
        if not api_file.is_file():
            continue
        raw = _load(api_file)
        if raw is None:
            continue

        actions = [
            a for f in sorted(api_dir.rglob("PolicyAction.*"))
            if f.is_file() and (a := _maybe_action(f)) is not None
        ]
        apis.append(_build_api(raw, actions, str(api_file.relative_to(root))))

    return GatewayExport(apis=apis, source=str(root))


def read_zip(path: str | Path) -> GatewayExport:
    """Liest einen Export direkt aus dem ZIP, ohne ihn auf Platte zu entpacken."""
    path = Path(path).expanduser()
    api_raw: dict[str, dict[str, Any]] = {}
    actions: dict[str, list[PolicyAction]] = {}

    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            name = parts[-1]
            if any(sperr in parts for sperr in GESPERRTE_ASSETS):
                continue

            api_key = next((p for p in parts if p.startswith("API.")), None)
            if api_key is None:
                continue
            try:
                data = json.loads(zf.read(info).decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                continue
            if not isinstance(data, dict):
                continue

            if name.startswith("PolicyAction."):
                actions.setdefault(api_key, []).append(_policy_action(data))
            elif name == api_key and "apiName" in data:
                api_raw[api_key] = data

    apis = [
        _build_api(raw, actions.get(key, []), key)
        for key, raw in sorted(api_raw.items())
    ]
    return GatewayExport(apis=apis, source=str(path))


def read_export(path: str | Path) -> GatewayExport:
    """Liest einen Export — ZIP oder entpacktes Verzeichnis."""
    p = Path(path).expanduser()
    if p.is_file() and zipfile.is_zipfile(p):
        return read_zip(p)
    return read_directory(p)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _maybe_action(path: Path) -> PolicyAction | None:
    raw = _load(path)
    return _policy_action(raw) if raw is not None else None
