"""Kommandozeile: ``oas-audit spec.yaml`` — Text- oder JSON-Ausgabe, kein Netzwerk."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from oas_audit import __version__
from oas_audit.audit import AuditResult, audit
from oas_audit.findings import Confidence, Finding
from oas_audit.parser.openapi import load_spec
from oas_audit.rules import check_ids
from oas_audit.scoring import Score, score

_SEV_KURZ = {"critical": "KRIT", "high": "HOCH", "medium": "MITTEL", "low": "NIEDRIG", "info": "INFO"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="oas-audit",
        description=("Statische OWASP-Security-Analyse einer OpenAPI-Spezifikation. "
                     "Sendet keinen einzigen Request an die beschriebene API."),
    )
    ap.add_argument("spec", nargs="?", help="Pfad zur Spezifikation (JSON oder YAML)")
    ap.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    ap.add_argument("--checks", action="store_true", help="alle Regelkennungen auflisten")
    ap.add_argument("--login", metavar="PFAD", help="Pfad der Login-Operation (z.B. /auth/login)")
    ap.add_argument("--lang", choices=["de", "en"], default="de", help="Sprache des Prüfsatzes")
    ap.add_argument("--catalog", action="store_true", help="nur den Prüfsatz als Markdown ausgeben")
    ap.add_argument("--version", action="version", version=f"oas-audit {__version__}")
    args = ap.parse_args(argv)

    if args.checks:
        print("\n".join(check_ids()))
        return 0
    if not args.spec:
        ap.error("Spezifikation angeben oder --checks verwenden")

    try:
        spec = load_spec(args.spec)
    except FileNotFoundError:
        print(f"Datei nicht gefunden: {args.spec}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — jeder Parse-Fehler ist hier ein Nutzerfehler
        print(f"Spezifikation nicht lesbar: {exc}", file=sys.stderr)
        return 2

    try:
        result = audit(spec, login_endpoint=args.login, lang=args.lang)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sc = score(result)

    if args.catalog:
        from oas_audit.catalog import to_markdown  # noqa: PLC0415

        print(to_markdown(result.catalog, args.lang, title=result.title))
        return 0
    if args.json:
        print(json.dumps(
            {"tool": {"name": "oas-audit", "version": __version__},
             "source": str(Path(args.spec).name),
             "result": result.model_dump(mode="json"),
             "score": sc.model_dump(mode="json")},
            indent=2, ensure_ascii=False,
        ))
    else:
        print(render_text(result, sc))
    return 0


def render_text(r: AuditResult, sc: Score) -> str:
    z: list[str] = []
    z.append(f"oas-audit {__version__} — {r.title or 'ohne Titel'} (OpenAPI {r.spec_version}, "
             f"{r.endpoint_count} Operationen, Hash {r.spec_hash})")
    z.append("")
    z.append(f"  Sicherheitsdesign:        {sc.design.letter}" + _cap_text(sc.design))
    z.append(f"  Spezifikationshygiene:    {sc.hygiene.letter}" + _cap_text(sc.hygiene))
    z.append(f"  Nur zur Laufzeit prüfbar: {sc.runtime_gap_count} Risikoklassen (unten aufgeführt)")
    z.append(f"  Prüfsatz:                 {len(r.catalog)} Testfälle (--catalog für Markdown)")
    z.append("")
    z.append(f"  {sc.note}")
    z.append("")

    belegt = [f for f in r.findings if f.confidence is Confidence.BELEGT and f.aggregate_count is None]
    hinweise = [f for f in r.findings if f.confidence is Confidence.WAHRSCHEINLICH and f.aggregate_count is None]
    aggregate = [f for f in r.findings if f.aggregate_count is not None]

    z.append(f"BELEGT — aus dem Dokument ablesbar ({len(belegt)})")
    z.extend(_finding_block(f) for f in belegt) if belegt else z.append("  keine")
    z.append("")
    z.append(f"WAHRSCHEINLICH — Prüfaufträge, nicht bewertet ({len(hinweise)})")
    z.extend(_finding_block(f) for f in hinweise) if hinweise else z.append("  keine")
    z.append("")
    z.append(f"STIL-BEOBACHTUNGEN — gesammelt ({len(aggregate)})")
    for f in aggregate:
        z.append(f"  [{_SEV_KURZ[f.severity.value]:7}] {f.check_id}: {f.title} — {f.subject}")
    if not aggregate:
        z.append("  keine")
    z.append("")
    z.append(f"BLINDSTELLEN — nicht ausgewertete Strukturen ({len(r.blind_spots)})")
    for b in r.blind_spots:
        z.append(f"  {b.pointer}: {b.what}")
        if b.why:
            z.append(f"      {b.why}")
    if not r.blind_spots:
        z.append("  keine")
    z.append("")
    z.append(f"NUR ZUR LAUFZEIT PRÜFBAR ({len(r.runtime_gaps)})")
    for g in r.runtime_gaps:
        z.append(f"  [{g.owasp.value if g.owasp else '-':4}] {g.title}")
    return "\n".join(z)


def _cap_text(g) -> str:
    if not g.capped:
        return f"   ({g.points} Punkte)"
    return f"   (rechnerisch {g.uncapped}, begrenzt durch: " + "; ".join(
        f"{c.check_id} → {c.cap}" for c in g.caps) + ")"


def _finding_block(f: Finding) -> str:
    kopf = f"  [{_SEV_KURZ[f.severity.value]:7}] {f.check_id}"
    wo = f"{f.method + ' ' if f.method else ''}{f.subject}"
    zeilen = [f"{kopf}  {wo}", f"      {f.title}"]
    if f.affected and len(f.affected) > 1:
        zeilen.append("      betrifft: " + ", ".join(f.affected[:6]) + (" …" if len(f.affected) > 6 else ""))
    for e in f.evidence[:2]:
        zeilen.append(f"      ↳ {e.pointer}" + (f"  ({e.excerpt})" if e.excerpt else ""))
    if f.cap:
        zeilen.append(f"      Deckel: Note höchstens {f.cap}")
    return "\n".join(zeilen)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
