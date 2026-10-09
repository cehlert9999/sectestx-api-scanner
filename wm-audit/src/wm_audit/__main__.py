"""Kommandozeile: ``wm-audit EXPORT [--json | --html] [--output DATEI] [--fail-on SCHWERE]``.

Exit-Codes: 0 = gelesen, 1 = ``--fail-on`` ausgelöst, 2 = Aufruf- oder Lesefehler.
Die Rust-Portierung hat dieselbe Schnittstelle.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from oas_audit.models import Severity

from wm_audit.bericht import WERKZEUG, als_html, als_json, als_text, bericht, ueber_schwelle
from wm_audit.reader import ExportFehler, read_export


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wm-audit",
        description="Statische Security-Analyse eines webMethods-API-Gateway-Exports.",
    )
    ap.add_argument("export", help="Export als ZIP-Datei oder entpacktes Verzeichnis")
    format_ = ap.add_mutually_exclusive_group()
    format_.add_argument("--json", action="store_true", help="Bericht als JSON ausgeben")
    format_.add_argument("--html", action="store_true",
                         help="Bericht als HTML-Datei mit Aufgabenliste (für Menschen)")
    ap.add_argument("--output", "-o", help="Bericht in diese Datei schreiben statt auf stdout")
    ap.add_argument("--fail-on", choices=[s.value for s in Severity],
                    help="Exit-Code 1, wenn ein belegter Befund mindestens diese Schwere hat")
    ap.add_argument("--version", action="version", version=WERKZEUG)
    args = ap.parse_args(argv)

    try:
        export = read_export(args.export)
    except (ExportFehler, OSError) as e:
        print(f"wm-audit: {e}", file=sys.stderr)
        return 2

    b = bericht(export)
    ausgabe = als_json(b) if args.json else als_html(b) if args.html else als_text(b)
    if args.output:
        try:
            Path(args.output).write_bytes(ausgabe.encode("utf-8"))
        except OSError as e:
            print(f"wm-audit: {e}", file=sys.stderr)
            return 2
    else:
        sys.stdout.buffer.write(ausgabe.encode("utf-8"))
        sys.stdout.flush()

    return 1 if args.fail_on and ueber_schwelle(b, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
