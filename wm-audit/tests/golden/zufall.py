"""Zufällige Exporte für den differenziellen Test Python ↔ Rust.

Die Golden-Fälle decken bekannte Grenzfälle ab; dieser Generator deckt die
unbekannten ab. Er mischt gültige und kaputte Assets, Werte jeden JSON-Typs,
mehrere Umgebungen, Aliase, Policy-Zuordnungen und gesperrte Einträge. Gleicher
Seed, gleicher Export — ein gefundener Unterschied ist reproduzierbar.
"""

from __future__ import annotations

import json
import random
import zipfile
from pathlib import Path

ZEIT = (1980, 1, 1, 0, 0, 0)

_URIS = ["http://a.example", "https://b.example", "HTTP://u:p@c.example/x", "ftp://d", "",
         "http://h/x@y", "https://u@e.example", 5, None, ["http://liste"]]
_BOOLS = [True, False, "true", "False", "TRUE", "yes", 1, 0, None, "", ["true"]]
_ROUTING = ["${A}/x", "${B}", "http://lit.example/${sys:resource_path}", "https://lit.example",
            "${A", "${a${A}}", "http://u:p@h.example", "${sys:x}${A}", 7]
_TYPEN = ["apiKey", "jwtClaims", "hostNameAddress", "hostName", "ipAddressRange", "oAuth2Token", "httpBasicAuth", 7,
          None]


def _zahl(r: random.Random):
    art = r.randrange(6)
    if art == 0:
        return r.randint(-(2**70), 2**70)
    if art == 1:
        return r.randint(-1000, 1000)
    if art == 2:
        return r.uniform(-1, 1) * 10 ** r.randint(-30, 30)
    if art == 3:
        return float(r.randint(0, 10**6))
    if art == 4:
        return r.choice([0.1 + 0.2, 1e16, 1e15, 9999999999999998.0, 1e-4, 1e-5, -0.0, 5e-324])
    return r.random()


def _skalar(r: random.Random):
    return r.choice([
        lambda: r.choice(["1.0", "v2", "Zähler", "x y", "", "🔌", "a\\b", 'q"uote']),
        lambda: _zahl(r),
        lambda: r.choice([True, False, None]),
        lambda: [r.choice(["a", 1, None])],
        lambda: {"k": 1},
    ])()


def _werte(r: random.Random, pool):
    art = r.randrange(5)
    if art == 0:
        return r.choice(pool)
    if art == 1:
        return None
    return [r.choice(pool) for _ in range(r.randint(0, 3))]


def _aktion(r: random.Random, aid: str) -> dict:
    key = r.choice(["entryProtocolPolicy", "evaluatePolicy", "throttle", "throttlingPolicy", "logInvocation",
                    "straightThroughRouting", "contentBasedRouting", "requestSizeLimit",
                    "trafficOptimizationPolicy", r.choice([5, None, "irgendwas"])])
    params: list = []
    if key == "entryProtocolPolicy":
        params.append({"templateKey": "protocol", "values": _werte(r, ["http", "https", "HTTP", "Http", 1])})
    elif key == "evaluatePolicy":
        params.append({"templateKey": "allowAnonymous", "values": _werte(r, ["true", True, "TRUE", "no"])})
        params.append({"templateKey": "logicalConnector", "values": _werte(r, ["OR", "or", "AND", "Or"])})
        for _ in range(r.randint(0, 3)):
            params.append({"templateKey": "IdentificationRule", "parameters": r.choice([
                [{"templateKey": "identificationType", "values": _werte(r, _TYPEN)}],
                [None, {"templateKey": "identificationType", "values": _werte(r, _TYPEN)}],
                "kaputt",
            ])})
    elif key in ("straightThroughRouting", "contentBasedRouting"):
        params.append({"templateKey": "endpointUri", "values": _werte(r, _ROUTING)})
    if r.random() < 0.2:
        params.append(r.choice([1, "x", None]))
    r.shuffle(params)
    return {"id": aid if r.random() < 0.95 else _skalar(r),
            "names": r.choice([[{"value": _skalar(r)}], [], "x", None, [{"value": "Name"}]]),
            "templateKey": key, "parameters": params if r.random() < 0.9 else _skalar(r),
            "active": _skalar(r)}


def _api(r: random.Random, name: str) -> dict:
    d: dict = {}
    if r.random() < 0.95:
        d["apiName"] = name if r.random() < 0.85 else _skalar(r)
    if r.random() < 0.9:
        d["apiVersion"] = r.choice(["1.0", "2.0"]) if r.random() < 0.5 else _skalar(r)
    eps = [{"uri": r.choice(_URIS), "passSecurityHeaders": r.choice(_BOOLS),
            "connectionTimeoutDuration": _skalar(r)} for _ in range(r.randint(0, 3))]
    d["nativeEndpoint"] = r.choice([eps, eps[0] if eps else None, "x", eps])
    for feld in ("id", "type", "isActive", "maturityState", "apiGroups"):
        if r.random() < 0.5:
            d[feld] = _skalar(r)
    return d


def _kaputt(r: random.Random) -> bytes:
    return r.choice([
        b'{"apiName": "K", ', b"[1]", b'{"apiName": "K\xe4"}', b"",
        b'{"apiName": "K", "x": ' + b"[" * r.randint(95, 105) + b"]" * 105 + b"}",
        b'{"apiName": "K", "x": NaN}', b'{"apiName": "K\\ud800"}', b'{"apiName": "K"} x',
        b'\xef\xbb\xbf{"apiName": "K"}', b'{"name": "ohne"}',
    ])


def export(seed: int) -> dict[str, bytes]:
    r = random.Random(seed)
    dateien: dict[str, bytes] = {}
    umgebungen = r.choice([[""], ["test/", "prod/"], ["a/assets/"]])
    namen = [f"Api{i}" for i in range(r.randint(1, 4))]
    for env in umgebungen:
        for n, name in enumerate(namen):
            basis = f"{env}assets/API/API.{n}"
            dateien[f"{basis}/API.{n}"] = (json.dumps(_api(r, name), ensure_ascii=r.random() < 0.5)
                                          .encode("utf-8") if r.random() < 0.9 else _kaputt(r))
            ids = [f"a{n}-{k}" for k in range(r.randint(0, 5))]
            for aid in ids:
                dateien[f"{basis}/Policy/Policy.p{n}/PolicyAction/PolicyAction.{aid}"] = (
                    json.dumps(_aktion(r, aid)).encode("utf-8") if r.random() < 0.95 else _kaputt(r))
            if r.random() < 0.6:
                zugeordnet = [i for i in ids if r.random() < 0.7]
                dateien[f"{basis}/Policy/Policy.p{n}/Policy.p{n}"] = json.dumps({
                    "id": f"p{n}",
                    "policyEnforcements": r.choice([
                        [{"stageKey": "s", "enforcements": [{"enforcementObjectId": i} for i in zugeordnet]}],
                        {}, None, [{"enforcements": "x"}], [1],
                    ]),
                }).encode("utf-8")
            if r.random() < 0.15:
                dateien[f"{basis}/Keystore/PolicyAction.geheim"] = b'{"templateKey": "evaluatePolicy"}'
        for k in range(r.randint(0, 3)):
            dateien[f"{env}assets/Alias/Alias.{k}"] = json.dumps({
                "name": r.choice(["A", "B", "A", 3]),
                "type": r.choice(["simple", "simple", "endpoint", None]),
                "value": r.choice(["http://alias.example", "https://alias.example",
                                   "http://u:p@alias.example", 9]),
            }).encode("utf-8")
        if r.random() < 0.3:
            dateien[f"{env}assets/PassmanData/PassmanData.{seed}"] = b'{"password": "GEHEIM"}'
    if r.random() < 0.2:
        dateien["assets/API/API.waise/Policy/Policy.w/PolicyAction/PolicyAction.w1"] = \
            json.dumps(_aktion(r, "w1")).encode("utf-8")
    return dateien


def schreibe(ziel: Path, dateien: dict[str, bytes], als_zip: bool) -> Path:
    if als_zip:
        pfad = ziel.with_suffix(".zip")
        with zipfile.ZipFile(pfad, "w") as zf:
            for rel in sorted(dateien):
                zi = zipfile.ZipInfo(rel, date_time=ZEIT)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zi, dateien[rel])
        return pfad
    for rel, daten in dateien.items():
        p = ziel / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(daten)
    return ziel
