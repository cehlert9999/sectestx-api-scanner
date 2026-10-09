"""Erzeugt die Golden-Fälle für wm-audit und — mit ``--erwartung`` — deren Soll-Ausgaben.

Die Golden-Files sind der Vertrag zwischen der Python-Referenz und der
Rust-Portierung (``code/wm-audit-rs``): beide müssen für jeden Fall in
``faelle.json`` byte-identisches JSON und identischen Text liefern und mit
demselben Exit-Code enden.

    python tests/golden/erzeugen.py               # Fälle (Verzeichnisse, ZIPs) neu bauen
    python tests/golden/erzeugen.py --erwartung   # zusätzlich Soll-Ausgaben aus Python schreiben

Die ZIPs sind deterministisch (feste Zeitstempel, sortierte Einträge). Nach
``--erwartung`` gehört jede Änderung an ``erwartet/`` durch einen Menschen
gelesen — sie ist eine Verhaltensänderung des Werkzeugs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path

HIER = Path(__file__).resolve().parent
FAELLE = HIER / "faelle"
ERWARTET = HIER / "erwartet"
FIXTURES = HIER.parent / "fixtures"

ZEIT = (1980, 1, 1, 0, 0, 0)
MIB = 1024 * 1024

MANIFEST = [
    {"name": "fixtures-verzeichnis", "pfad": "../fixtures"},
    {"name": "fixtures-zip", "pfad": "faelle/fixtures.zip"},
    {"name": "umgebungen-verzeichnis", "pfad": "faelle/umgebungen"},
    {"name": "umgebungen-zip", "pfad": "faelle/umgebungen.zip"},
    {"name": "robust-verzeichnis", "pfad": "faelle/robust"},
    {"name": "robust-zip", "pfad": "faelle/robust.zip"},
    {"name": "aggregat", "pfad": "faelle/aggregat"},
    {"name": "leer", "pfad": "faelle/leer"},
    {"name": "fail-on-critical", "pfad": "../fixtures", "argumente": ["--fail-on", "critical"],
     "exit": 1, "nur_exit": True},
    {"name": "fail-on-ohne-treffer", "pfad": "faelle/aggregat", "argumente": ["--fail-on", "critical"],
     "exit": 0, "nur_exit": True},
    {"name": "doppelt-zip", "pfad": "faelle/doppelt.zip", "exit": 2, "nur_exit": True},
    {"name": "kein-zip", "pfad": "faelle/kein-zip.txt", "exit": 2, "nur_exit": True},
    {"name": "fehlt", "pfad": "faelle/gibt-es-nicht", "exit": 2, "nur_exit": True},
]


# ---------------------------------------------------------------- Bausteine


def j(obj) -> bytes:
    return (json.dumps(obj, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def api(name, version="1.0", native=None, **extra) -> dict:
    d = {"apiName": name, "apiVersion": version, "type": "REST",
         "nativeEndpoint": native if native is not None
         else [{"uri": "https://backend.example", "passSecurityHeaders": False}]}
    d.update(extra)
    return d


def aktion(aid, key, params, name="Aktion") -> dict:
    return {"id": aid, "names": [{"value": name, "locale": "en"}], "templateKey": key,
            "parameters": params, "active": False}


def proto(aid, *p):
    return aktion(aid, "entryProtocolPolicy", [{"templateKey": "protocol", "values": list(p)}], "Protocol")


def ident(aid, *typen, connector="AND"):
    return aktion(aid, "evaluatePolicy", [
        {"templateKey": "logicalConnector", "values": [connector]},
        *[{"templateKey": "IdentificationRule",
           "parameters": [{"templateKey": "identificationType", "values": [t]}]} for t in typen],
    ], "Identify & Authorize")


def limit(aid):
    return aktion(aid, "throttle", [{"templateKey": "throttleRule", "parameters": [
        {"templateKey": "throttleRuleName", "values": ["requestCount"]},
        {"templateKey": "monitorRuleOperator", "values": ["GT"]},
        {"templateKey": "value", "values": ["100"]}]}], "Traffic Optimization")


def routing(aid, uri, key="straightThroughRouting"):
    return aktion(aid, key, [{"templateKey": "endpointUri", "values": [uri]}], "Routing")


def policy(pid, *ids):
    return {"id": pid, "policyEnforcements": [
        {"stageKey": "alle", "enforcements": [{"enforcementObjectId": i, "order": "0"} for i in ids]}]}


def api_dateien(wurzel: str, uid: str, raw: dict, aktionen=(), policy_raw=None) -> dict[str, bytes]:
    basis = f"{wurzel}/API/API.{uid}" if wurzel else f"API/API.{uid}"
    d = {f"{basis}/API.{uid}": j(raw)}
    if policy_raw is not None:
        d[f"{basis}/Policy/Policy.p{uid}/Policy.p{uid}"] = j(policy_raw)
    for a in aktionen:
        d[f"{basis}/Policy/Policy.p{uid}/PolicyAction/PolicyAction.{a['id']}"] = j(a)
    return d


def alias_datei(wurzel: str, aid: str, name: str, wert: str, typ="simple") -> dict[str, bytes]:
    pfad = f"{wurzel}/Alias/Alias.{aid}" if wurzel else f"Alias/Alias.{aid}"
    return {pfad: j({"id": aid, "name": name, "type": typ, "value": wert})}


# ---------------------------------------------------------------- Fälle


def umgebungen() -> dict[str, bytes]:
    d: dict[str, bytes] = {}
    for env, mit_identify, backend in (("test", False, "http://test-backend.intern"),
                                       ("prod", True, "https://prod-backend.intern")):
        akt = [proto("u1-p", "https"), limit("u1-l"), routing("u1-r", "${Backend}/${sys:resource_path}")]
        if mit_identify:
            akt.append(ident("u1-i", "jwtClaims"))
        d |= api_dateien(f"{env}/assets", "u1", api("UmgebungsAPI"), akt)
        d |= api_dateien(f"{env}/assets", "u2", api("NachbarAPI"),
                         [proto("u2-p", "https"), limit("u2-l"), ident("u2-i", "oAuth2Token")])
        d |= alias_datei(f"{env}/assets", f"al-{env}", "Backend", backend)
    return d


def robust() -> dict[str, bytes]:
    d: dict[str, bytes] = {}

    # Wahrheitswerte als Text, Skalare statt Listen, Fremdkörper in Listen
    d |= api_dateien("assets", "r1", {
        "apiName": "R1", "apiVersion": 2, "isActive": "FALSE", "apiGroups": "x",
        "nativeEndpoint": {"uri": "https://r1.example", "passSecurityHeaders": "False",
                           "connectionTimeoutDuration": "12"},
    }, [
        aktion("r1-a", "entryProtocolPolicy", [1, "x", {"templateKey": "protocol", "values": "HTTP"}]),
        {"id": "r1-b", "names": [], "templateKey": "evaluatePolicy", "parameters": [
            {"templateKey": "allowAnonymous", "values": [True]},
            {"templateKey": "logicalConnector", "values": ["or"]},
            {"templateKey": "IdentificationRule",
             "parameters": [{"templateKey": "identificationType", "values": ["apiKey"]}]},
            {"templateKey": "IdentificationRule",
             "parameters": [None, {"templateKey": "identificationType", "values": ["hostName", 7]}]},
        ]},
    ])

    # Versionsangaben jeder Art — die Lesart muss in Python und Rust gleich sein
    versionen = {
        "r2": 1.5, "r3": 1e16, "r4": 0.0001, "r5": 0.00001, "r6": -0.0, "r8": None, "r9": True,
        "r10": [1], "r13": 100.0, "r20": 123456789.125, "r21": 1e-7, "r22": 9007199254740993.0,
    }
    for uid, v in versionen.items():
        d |= api_dateien("assets", uid, api(uid.upper(), v))
    roh = {
        "r7": '{"apiName": "R7", "apiVersion": 12345678901234567890123}',
        "r11": '{"apiName": "R11", "apiVersion": 18446744073709551615}',
        "r12": '{"apiName": "R12", "apiVersion": -9223372036854775808}',
        "r14": '{"apiName": "R14", "apiVersion": 1E2}',
        "r15": '{"apiName": "erst", "apiName": "R15", "apiVersion": "1"}',
        "r16": '{"apiName": "Zählerstände 🔌", "apiVersion": "β"}',
        "r17": '{"apiName": "R17", "apiVersion": 1.0e-5}',
        "r18": '{"apiName": "R18", "apiVersion": 18446744073709551616}',
        "r19": '{"apiName": "R19", "apiVersion": -9223372036854775809}',
        "r23": '{"apiName": "R23", "apiVersion": 0.1e1}',
        "r24": '{"apiName": "R24", "apiVersion": 5e-324}',
        "r25": '{"apiName": "R25", "apiVersion": 1.7976931348623157e308}',
        "r26": '{"apiName": "R26", "apiVersion": -0}',
        "r27": '{"apiName": "R27", "apiVersion": 0.30000000000000004}',
    }
    for uid, text in roh.items():
        d[f"assets/API/API.{uid}/API.{uid}"] = text.encode("utf-8")

    # Kaputte und grenzwertige Dateien
    kaputt = {
        "k1": b'{"apiName": "K1", ',
        "k2": b"[1, 2]",
        "k3": b'{"apiName": "K\xe4se"}',
        "k4": b'{"apiName": "K4", "x": ' + b"[" * 100 + b"]" * 100 + b"}",
        "k5": b'{"apiName": "K5", "x": NaN}',
        "k6": b'{"apiName": "K6", "x": 1e400}',
        "k7": b'{"apiName": "K7\\ud800"}',
        "k8": b'{"apiName": "K8\\udc00x"}',
        "k9": b'\xef\xbb\xbf{"apiName": "K9"}',
        "k10": b'{"name": "ohne apiName"}',
        "k11": b'{"apiName": "K11", "x": ' + b"[" * 99 + b"]" * 99 + b"}",
        "k12": b'{"apiName": "K12", "s": "\\"' + b"[" * 300 + b'\\\\", "t": "{{{"}',
        "k13": b'{"apiName": "K\tb"}',
        "k14": b'{"apiName": "K14"} x',
        "k15": b'{"apiName": "K15", "n": 01}',
        "k16": b'\r\n\t {"apiName": "K16"}\n',
        "k17": b'{"apiName": "K17", "x": -}',
        "k18": b'{"apiName": "K18", "x": "\\u00e4\\ud83d\\ude00"}',
        "k19": b'{"apiName": 5}',
        "k20": b'{"apiName": "K20", "nativeEndpoint": [{"uri": "HTTP://USER:pw@K20.example"}]}',
        "k21": b'{"apiName": "K21", "x": Infinity}',
        "k22": b'{"apiName": "K22", "x": [1, 2,]}',
        "k23": b'{"apiName": "K23", "x": "\\x"}',
        "k24": b"",
        "k25": b'"nur ein String"',
        "k26": b'{"apiName": "K26", "x": ' + b"{" * 120 + b"}" * 120 + b"}",
        "k27": b'{"apiName": "K27", "x": "' + b"]" * 50 + b'"}',
        "k28": b'{"apiName": "K28"}' + b"\x00",
        "k29": b'{"apiName": "K\xc3\x28"}',
        "k30": b'{"apiName": "K30", "x": "\\u0041\\u00DF"}',
    }
    for uid, daten in kaputt.items():
        d[f"assets/API/API.{uid}/API.{uid}"] = daten

    # Verwaiste und nicht zugeordnete Aktionen, mehrere Policies je API
    d["assets/API/API.oz/Policy/Policy.poz/PolicyAction/PolicyAction.o1"] = j(proto("o1", "http"))
    d |= api_dateien("assets", "n1", api("N1"), [ident("n1-a", "jwtClaims"), proto("n1-b", "http"),
                                                 limit("n1-c")], policy("pn1", "n1-a"))
    d["assets/API/API.n1/Policy/Policy.qn1/Policy.qn1"] = j(policy("qn1", "n1-c"))
    d |= api_dateien("assets", "n2", api("N2"), [proto("n2-a", "http")],
                     {"id": "pn2", "policyEnforcements": {}})

    # Verschachtelte API-Verzeichnisse: die Aktion gehört zur innersten API
    d["assets/API/API.aussen/API.aussen"] = j(api("Aussen"))
    d["assets/API/API.aussen/unter/API.innen/API.innen"] = j(api("Innen"))
    d["assets/API/API.aussen/unter/API.innen/Policy/Policy.pi/PolicyAction/PolicyAction.i1"] = \
        j(ident("i1", "oAuth2Token"))

    # Aliase: nächste Wurzel gewinnt, nur "simple", erster Pfad bei Namensgleichheit
    d |= alias_datei("", "x", "Ziel", "http://wurzel.example")
    d |= alias_datei("env", "y", "Ziel", "https://env.example")
    d |= alias_datei("", "z", "Ziel2", "http://endpoint.example", typ="endpoint")
    d |= alias_datei("", "a1", "Dup", "http://erster.example")
    d |= alias_datei("", "a2", "Dup", "https://zweiter.example")
    d |= api_dateien("env", "e1", api("E1"), [routing("e1-r", "${Ziel}/x")])
    d |= api_dateien("", "e2", api("E2"), [routing("e2-r", "${Ziel}/x")])
    d |= api_dateien("", "e3", api("E3"), [routing("e3-r", "${Ziel2}/x")])
    d |= api_dateien("", "e4", api("E4"), [routing("e4-r", "${Dup}")])
    d |= api_dateien("", "e5", api("E5", native=[{"uri": "http://e5.example"}]),
                     [routing("e5-r", "https://e5.example", key="contentBasedRouting")])
    d |= api_dateien("", "e6", api("E6", native=[{"uri": "http://a.example"}, {"uri": "http://b.example"}]))
    d |= api_dateien("", "e7", api("E7"), [routing("e7-r", "http://lit.example/${sys:resource_path}")])
    d |= api_dateien("", "e8", api("E8"), [routing("e8-r", "${Ziel")])
    d |= api_dateien("", "e9", api("E9"), [routing("e9-r", "${a${Ziel}}")])
    d |= api_dateien("", "e10", api("E10"), [routing("e10-r", "http://u@v:w@host.example:1/p?q=@#f")])

    # Gesperrt — darf nie geöffnet werden; PassmanDataX ist es nicht
    d["assets/PassmanData/PassmanData.p1"] = j({"password": "GEHEIM-KANARIE"})
    d["assets/API/API.r2/keystore.k"] = j({"apiName": "GEHEIM-KANARIE"})
    d["KERBEROS/API.kb/API.kb"] = j({"apiName": "GEHEIM-KANARIE"})
    d["assets/API/API.r2/Policy/Policy.pr2/PolicyAction/Truststore"] = j(ident("t", "apiKey"))
    d["PassmanDataX/API.px/API.px"] = j({"apiName": "PX nicht gesperrt"})

    # Rauschen, das nie gelesen werden darf
    d["assets/API/API.r2/._API.r2"] = b"\x00\x05\x16\x07Mac OS X"
    d["assets/API/API.r2/notizen.json"] = j({"apiName": "Rauschen"})
    return d


def aggregat() -> dict[str, bytes]:
    d: dict[str, bytes] = {}
    for i in range(1, 6):
        akt = [ident(f"g{i}-i", "jwtClaims"), proto(f"g{i}-p", "http" if i <= 3 else "https")]
        if i > 3:
            akt.append(limit(f"g{i}-l"))
        native = [{"uri": f"{'http' if i <= 2 else 'https'}://g{i}.example"}]
        d |= api_dateien("assets", f"g{i}", api(f"G{i}", native=native), akt)
    return d


# ---------------------------------------------------------------- Schreiben


def schreibe_verzeichnis(ziel: Path, dateien: dict[str, bytes]) -> None:
    if ziel.exists():
        shutil.rmtree(ziel)
    ziel.mkdir(parents=True)
    for rel, daten in dateien.items():
        p = ziel / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(daten)


def _info(name: str, art=zipfile.ZIP_DEFLATED) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name, date_time=ZEIT)
    zi.compress_type = art
    zi.external_attr = 0o644 << 16
    return zi


def schreibe_zip(ziel: Path, dateien: dict[str, bytes], extra=()) -> None:
    with zipfile.ZipFile(ziel, "w") as zf:
        for rel in sorted(dateien):
            zf.writestr(_info(rel), dateien[rel])
        for name, daten, art in extra:
            zf.writestr(_info(name, art), daten)


def verzeichnis_als_dict(wurzel: Path) -> dict[str, bytes]:
    return {p.relative_to(wurzel).as_posix(): p.read_bytes()
            for p in sorted(wurzel.rglob("*")) if p.is_file()}


def _setze_flag(daten: bytearray, name: bytes, bit: int) -> None:
    """Setzt ein Bit im General-Purpose-Flag von lokalem und zentralem Header."""
    for sig, flag_ofs, name_ofs in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
        start = 0
        while (i := daten.find(sig, start)) >= 0:
            if daten[i + name_ofs:i + name_ofs + len(name)] == name:
                daten[i + flag_ofs] |= bit
            start = i + 4


def robust_zip(ziel: Path, dateien: dict[str, bytes]) -> None:
    gross = b'{"apiName": "G"}' + b" " * (32 * MIB + 1 - 16)
    genau = b'{"apiName": "G2"}' + b" " * (32 * MIB - 17)
    assert len(gross) == 32 * MIB + 1 and len(genau) == 32 * MIB
    extra = [
        ("win\\API\\API.w1\\API.w1", j(api("W1")), zipfile.ZIP_DEFLATED),
        ("./dot/API/API.d1/API.d1", j(api("D1")), zipfile.ZIP_DEFLATED),
        ("bz/API/API.bz/API.bz", j(api("BZ")), zipfile.ZIP_BZIP2),
        ("gross/API/API.g/API.g", gross, zipfile.ZIP_DEFLATED),
        ("gross/API/API.g2/API.g2", genau, zipfile.ZIP_DEFLATED),
        ("crc/API/API.c/API.c", b'{"apiName": "CRCX"}', zipfile.ZIP_STORED),
        ("enc/API/API.e/API.e", b'{"apiName": "ENC"}', zipfile.ZIP_STORED),
        ("leerordner/", b"", zipfile.ZIP_STORED),
        ("Keystore.jks", b"\x00GEHEIM-KANARIE", zipfile.ZIP_STORED),
    ]
    schreibe_zip(ziel, dateien, extra)
    daten = bytearray(ziel.read_bytes())
    i = daten.find(b'"CRCX"')
    daten[i + 4] = ord("Y")  # Inhalt ändern, CRC bleibt → Prüfsummenfehler
    _setze_flag(daten, b"enc/API/API.e/API.e", 0x1)
    ziel.write_bytes(bytes(daten))


def doppelt_zip(ziel: Path) -> None:
    with zipfile.ZipFile(ziel, "w") as zf, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for _ in range(2):
            zf.writestr(_info("API/API.x/API.x"), j(api("X")))


def faelle_bauen() -> None:
    FAELLE.mkdir(parents=True, exist_ok=True)
    schreibe_zip(FAELLE / "fixtures.zip", verzeichnis_als_dict(FIXTURES))
    u = umgebungen()
    schreibe_verzeichnis(FAELLE / "umgebungen", u)
    schreibe_zip(FAELLE / "umgebungen.zip", u)
    r = robust()
    schreibe_verzeichnis(FAELLE / "robust", r)
    robust_zip(FAELLE / "robust.zip", r)
    schreibe_verzeichnis(FAELLE / "aggregat", aggregat())
    schreibe_verzeichnis(FAELLE / "leer", {".gitkeep": b""})
    doppelt_zip(FAELLE / "doppelt.zip")
    (FAELLE / "kein-zip.txt").write_text("Das ist kein ZIP.\n", encoding="utf-8")
    (HIER / "faelle.json").write_text(json.dumps(MANIFEST, indent=1, ensure_ascii=False) + "\n",
                                      encoding="utf-8")


def erwartung_schreiben() -> None:
    ERWARTET.mkdir(exist_ok=True)
    for fall in MANIFEST:
        if fall.get("nur_exit"):
            continue
        pfad = str((HIER / fall["pfad"]).resolve())
        for endung, argumente in (("json", ["--json"]), ("txt", []), ("html", ["--html"])):
            lauf = subprocess.run([sys.executable, "-m", "wm_audit", pfad, *argumente],
                                  capture_output=True, check=False)
            assert lauf.returncode == fall.get("exit", 0), (fall, lauf.stderr)
            (ERWARTET / f"{fall['name']}.{endung}").write_bytes(lauf.stdout)


if __name__ == "__main__":
    faelle_bauen()
    if "--erwartung" in sys.argv:
        erwartung_schreiben()
    print("Golden-Fälle geschrieben:", FAELLE)
