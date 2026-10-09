"""Reader, Lesart und Sicherheitsgrenzen.

Jeder Test hier beschreibt eine Eigenschaft, die die Rust-Portierung ebenfalls
erfüllen muss — die Golden-Files (``test_golden.py``) prüfen die Gleichheit,
diese Tests das gewollte Verhalten.
"""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from wm_audit import (
    ExportFehler,
    Grenzen,
    bericht,
    read_directory,
    read_export,
    read_zip,
    run_rules,
    werte,
)
from wm_audit.__main__ import main
from wm_audit.models import aufloesen
from wm_audit.reader import ist_gesperrt
from wm_audit.rules import ohne_zugangsdaten

HIER = Path(__file__).parent
FIXTURES = HIER / "fixtures"
FAELLE = HIER / "golden" / "faelle"


def _ohne_quelle(b: dict) -> dict:
    return {k: v for k, v in b.items() if k != "quelle"}


# ---------------------------------------------------------------- ZIP = Verzeichnis


@pytest.mark.parametrize("name", ["fixtures", "umgebungen"])
def test_zip_und_verzeichnis_liefern_dasselbe(name):
    verzeichnis = FIXTURES if name == "fixtures" else FAELLE / name
    a = bericht(read_directory(verzeichnis))
    b = bericht(read_zip(FAELLE / f"{name}.zip"))
    assert _ohne_quelle(a) == _ohne_quelle(b)


@pytest.mark.parametrize("quelle", ["umgebungen", "umgebungen.zip"])
def test_policy_aus_prod_verdeckt_keine_luecke_in_test(quelle):
    """Regression: der ZIP-Reader verschmolz gleichnamige APIs mehrerer Umgebungen."""
    export = read_export(FAELLE / quelle)
    assert len(export.apis) == 4
    treffer = {(f.check_id, f.subject) for f in run_rules(export)}
    assert ("gw.no_identify_policy", "UmgebungsAPI 1.0") in treffer
    assert ("gw.plaintext_backend", "UmgebungsAPI 1.0") in treffer


# ---------------------------------------------------------------- Lesart


@pytest.mark.parametrize(("wert", "standard", "soll"), [
    (True, False, True), (False, True, False), ("false", True, False), ("False", True, False),
    ("TRUE", False, True), (" true", False, False), ("ja", True, True), (1, False, False),
    (None, True, True), ([True], False, False),
])
def test_wahrheitswert(wert, standard, soll):
    assert werte.wahrheitswert(wert, standard) is soll


@pytest.mark.parametrize(("wert", "soll"), [
    ("x", "x"), (True, "true"), (2, "2"), (1.0, "1.0"), (1e16, "1e+16"), (1e-5, "1e-05"),
    (-0.0, "-0.0"), (0.0001, "0.0001"), (None, ""), ([1], ""), ({"a": 1}, ""),
])
def test_text(wert, soll):
    assert werte.text(wert) == soll


@pytest.mark.parametrize(("quelle", "tiefe"), [
    ("{}", 1), ('{"a": [[1]]}', 3), ('"[[["', 0), ('{"a": "\\"[["}', 1),
    ('["\\\\", [1]]', 2), ("]]]", 0), ('{"a": "\\', 1),
])
def test_verschachtelung(quelle, tiefe):
    assert werte.verschachtelung(quelle) == tiefe


@pytest.mark.parametrize("quelle", ["NaN", "[Infinity]", "1e400", '"\\ud800"', '"\\udc00"', "01"])
def test_lade_json_ist_strikt(quelle):
    with pytest.raises(werte.JsonFehler):
        werte.lade_json(quelle)


def test_lade_json_grosse_ganzzahl_wird_float():
    assert werte.lade_json("18446744073709551615") == 18446744073709551615
    assert isinstance(werte.lade_json("18446744073709551616"), float)


# ---------------------------------------------------------------- Pfade, Aliase, URIs


@pytest.mark.parametrize(("teile", "soll"), [
    (["assets", "PassmanData", "x"], True), (["keystore.jks"], True), (["KERBEROS"], True),
    (["Keystore"], True),  # Kelvin-Zeichen wird klein zu "k"
    (["PassmanDataX"], False), (["Keystores"], False), (["API.Truststore"], False),
])
def test_ist_gesperrt(teile, soll):
    assert ist_gesperrt(teile) is soll


@pytest.mark.parametrize(("uri", "soll"), [
    ("http://u:p@h/x", "http://***@h/x"), ("http://h/x@y", "http://h/x@y"),
    ("http://a@b@h?q=@", "http://***@h?q=@"), ("ftp://h", "ftp://h"), ("kein uri @", "kein uri @"),
    ("HTTP://U@H", "HTTP://***@H"),
])
def test_ohne_zugangsdaten(uri, soll):
    assert ohne_zugangsdaten(uri) == soll


@pytest.mark.parametrize(("uri", "soll"), [
    ("${A}/x", "http://a/x"), ("${sys:resource_path}", "${sys:resource_path}"),
    ("${A", "${A"), ("${a${A}}", "${a${A}}"), ("${A}${A}", "http://ahttp://a"), ("", ""),
])
def test_aufloesen(uri, soll):
    assert aufloesen(uri, {"A": "http://a"}) == soll


# ---------------------------------------------------------------- Dateisystem


def _mini_export(wurzel: Path, name: str = "Mini") -> None:
    p = wurzel / "API" / "API.m" / "API.m"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"apiName": name}), encoding="utf-8")


def test_symlinks_werden_nicht_verfolgt(tmp_path):
    draussen = tmp_path / "draussen"
    draussen.mkdir()
    (draussen / "API.s").write_text('{"apiName": "GEHEIM-KANARIE"}', encoding="utf-8")
    export = tmp_path / "export"
    _mini_export(export)
    (export / "API" / "API.s").mkdir()
    os.symlink(draussen / "API.s", export / "API" / "API.s" / "API.s")
    os.symlink(draussen, export / "API" / "API.ordner")

    e = read_directory(export)
    assert [a.name for a in e.apis] == ["Mini"]
    assert [(u.grund, u.pfad) for u in e.uebersprungen] == [("symlink", "API/API.s/API.s")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="nur POSIX")
def test_fifo_wird_nicht_gelesen(tmp_path):
    """Ein FIFO würde beim Lesen blockieren — er wird gar nicht erst geöffnet."""
    _mini_export(tmp_path)
    (tmp_path / "API" / "API.f").mkdir()
    os.mkfifo(tmp_path / "API" / "API.f" / "API.f")
    assert [a.name for a in read_directory(tmp_path).apis] == ["Mini"]


# ---------------------------------------------------------------- Grenzen


def test_grenze_je_datei(tmp_path):
    _mini_export(tmp_path, name="x" * 200)
    e = read_directory(tmp_path, Grenzen(datei=100))
    assert [u.grund for u in e.uebersprungen] == ["zu_gross"]


def test_grenze_gesamt_bricht_ab():
    with pytest.raises(ExportFehler):
        read_export(FIXTURES, Grenzen(gesamt=1000))


@pytest.mark.parametrize("quelle", [FIXTURES, FAELLE / "fixtures.zip"])
def test_grenze_eintraege_bricht_ab(quelle):
    with pytest.raises(ExportFehler):
        read_export(quelle, Grenzen(eintraege=3))


def test_grenze_tiefe(tmp_path):
    p = tmp_path / "API" / "API.t" / "API.t"
    p.parent.mkdir(parents=True)
    p.write_text('{"apiName": "T", "x": [[[]]]}', encoding="utf-8")
    assert [u.grund for u in read_directory(tmp_path, Grenzen(tiefe=3)).uebersprungen] == ["zu_tief"]
    assert read_directory(tmp_path, Grenzen(tiefe=4)).apis[0].name == "T"


def test_zip_bombe_wird_nicht_ausgepackt(tmp_path):
    """1 GiB Nullen komprimieren auf rund 1 MB — gelesen wird höchstens die Grenze."""
    ziel = tmp_path / "bombe.zip"
    with zipfile.ZipFile(ziel, "w", zipfile.ZIP_DEFLATED) as zf, \
            zf.open("API/API.b/API.b", "w", force_zip64=True) as fh:
        block = b"\0" * (1 << 20)
        for _ in range(1024):
            fh.write(block)
    e = read_zip(ziel, Grenzen(datei=1 << 20))
    assert [u.grund for u in e.uebersprungen] == ["zu_gross"]


@pytest.mark.parametrize("name", ["doppelt.zip", "kein-zip.txt"])
def test_kaputte_archive(name):
    with pytest.raises(ExportFehler):
        read_export(FAELLE / name)


# ---------------------------------------------------------------- CLI


def test_cli_output_und_fail_on(tmp_path, capsysbinary):
    ziel = tmp_path / "bericht.json"
    assert main([str(FIXTURES), "--json", "--output", str(ziel), "--fail-on", "critical"]) == 1
    assert capsysbinary.readouterr().out == b""
    assert json.loads(ziel.read_text(encoding="utf-8"))["format"] == "wm-audit-bericht/1"
    assert main([str(FAELLE / "aggregat"), "--fail-on", "critical"]) == 0
    assert main([str(FAELLE / "aggregat"), "--fail-on", "high"]) == 1
    assert main([str(FAELLE / "aggregat"), "--fail-on", "info"]) == 1


def test_cli_fehler_ergibt_exit_2(capsys):
    assert main([str(FAELLE / "gibt-es-nicht")]) == 2
    assert "wm-audit:" in capsys.readouterr().err


# ---------------------------------------------------------------- HTML-Bericht


def test_html_bericht_laesst_keinen_code_aus_dem_export_durch(tmp_path):
    """Ein API-Name mit Skript-Tags darf den JSON-Datenblock nicht verlassen."""
    from wm_audit import als_html
    from wm_audit.bericht import _VORLAGE

    boese = '</script><script>alert(1)</script><!--'
    _mini_export(tmp_path, name=boese)
    html = als_html(bericht(read_directory(tmp_path)))
    vorlage = _VORLAGE.read_text(encoding="utf-8")
    assert html.count("</script>") == vorlage.count("</script>")
    assert "<script>alert" not in html and "<!--" not in html.replace(vorlage.split("__WM")[0], "")
    assert "\\u003c/script>\\u003cscript>alert(1)" in html


def test_html_vorlage_laedt_nichts_nach():
    from wm_audit.bericht import _VORLAGE

    vorlage = _VORLAGE.read_text(encoding="utf-8")
    assert "default-src 'none'" in vorlage
    assert ".innerHTML" not in vorlage and "insertAdjacentHTML" not in vorlage
    for verboten in ("fetch(", "XMLHttpRequest", "import(", "<link", "src=\"http"):
        assert verboten not in vorlage, verboten


def test_html_vorlage_gleich_in_rust():
    from wm_audit.bericht import _VORLAGE

    rust = HIER.parents[1] / "wm-audit-rs" / "src" / "bericht.html"
    if rust.is_file():
        assert rust.read_bytes() == _VORLAGE.read_bytes()
