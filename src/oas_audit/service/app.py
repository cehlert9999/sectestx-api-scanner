"""FastAPI-Anwendung des öffentlichen Scan-Dienstes."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from oas_audit import __version__
from oas_audit.rules import LAUFZEIT_LUECKEN, check_ids
from oas_audit.scoring import TESTREIFE_SATZ
from oas_audit.service.limits import RateLimiter
from oas_audit.service.loader import SpecError
from oas_audit.service.sandbox import ScanCrashed, ScanTimeout, run_isolated
from oas_audit.service.settings import Settings
from oas_audit.service.signing import sign, verify

log = logging.getLogger("oas_audit.service")


def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or Settings()
    app = FastAPI(
        title="oas-audit",
        version=__version__,
        description=("Statische OWASP-Security-Analyse einer OpenAPI-Spezifikation. "
                     "Die Spezifikation wird nur im Arbeitsspeicher verarbeitet, nie gespeichert, "
                     "und es wird kein Request an die beschriebene API gesendet."),
        docs_url=None, redoc_url=None, openapi_url="/api/v1/openapi.json",
    )
    if s.allowed_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=s.allowed_origins, allow_methods=["POST", "GET"],
            allow_headers=["Content-Type"], max_age=600,
        )
    limiter = RateLimiter(secret=s.secret, per_hour=s.scans_per_hour, per_day=s.scans_per_day,
                          global_per_day=s.global_scans_per_day)
    sem = asyncio.Semaphore(s.parallel_scans)
    app.state.settings = s
    app.state.limiter = limiter

    @app.middleware("http")
    async def sicherheits_header(request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/checks")
    async def checks() -> dict[str, Any]:
        return {"version": __version__, "checks": check_ids(),
                "runtime_gaps": [g.model_dump(mode="json") for g in LAUFZEIT_LUECKEN]}

    @app.post("/api/v1/scan")
    async def scan(request: Request) -> JSONResponse:
        ip = _client_ip(request, s.trust_proxy)
        erlaubt, grund, warte = limiter.check(ip)
        if not erlaubt:
            return JSONResponse({"error": grund}, status_code=429, headers={"Retry-After": str(max(warte, 1))})

        daten, hint, login = await _lese_spec(request, s.max_upload_bytes)
        lang = "en" if (request.query_params.get("lang") or _body_lang.get(id(request), "de")) == "en" else "de"

        async with sem:
            try:
                nutzlast = await asyncio.to_thread(
                    run_isolated, daten, hint=hint, login=login, lang=lang,
                    memory=s.worker_memory_bytes, cpu=s.worker_cpu_seconds, wall=s.worker_wall_seconds,
                )
            except SpecError as exc:
                raise HTTPException(422, str(exc)) from exc
            except ScanTimeout as exc:
                raise HTTPException(422, "Die Analyse hat das Zeitlimit überschritten. "
                                         "Das Dokument ist zu groß oder zu komplex.") from exc
            except ScanCrashed as exc:
                log.warning("Arbeitsprozess abgebrochen: %s", exc)
                raise HTTPException(500, "Die Analyse konnte nicht abgeschlossen werden.") from exc
        del daten

        _body_lang.pop(id(request), None)
        antwort = _antwort(nutzlast)
        antwort["signature"] = sign(antwort, s.secret)
        return JSONResponse(antwort)

    @app.post("/api/v1/report")
    async def report(body: dict[str, Any]) -> JSONResponse:
        """Prüfbericht als PDF — kommt in v1.1. Die Signaturprüfung steht schon."""
        ergebnis = body.get("result")
        signatur = body.get("signature")
        if not isinstance(ergebnis, dict) or not verify(ergebnis, signatur, s.secret):
            raise HTTPException(400, "Ergebnis ist nicht signiert oder wurde verändert.")
        raise HTTPException(501, "Der PDF-Prüfbericht ist noch nicht verfügbar.")

    return app


#: Sprache aus einem JSON-Body, je Request gemerkt (der Body ist nach dem Lesen weg).
_body_lang: dict[int, str] = {}


async def _lese_spec(request: Request, maximal: int) -> tuple[bytes, str, str | None]:
    """Liest die Spezifikation streamend und bricht *vor* dem Überschreiten des Limits ab."""
    laenge = request.headers.get("content-length")
    if laenge and laenge.isdigit() and int(laenge) > maximal:
        raise HTTPException(413, f"Dokument größer als {maximal // 1024 // 1024} MB.")

    ctype = request.headers.get("content-type", "")
    puffer = bytearray()
    async for chunk in request.stream():
        puffer.extend(chunk)
        if len(puffer) > maximal:
            raise HTTPException(413, f"Dokument größer als {maximal // 1024 // 1024} MB.")
    rohdaten = bytes(puffer)
    del puffer

    if ctype.startswith("multipart/form-data"):
        return _aus_multipart(rohdaten, ctype)
    if ctype.startswith("application/json"):
        import json  # noqa: PLC0415

        try:
            body = json.loads(rohdaten)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, "Anfrage ist kein gültiges JSON.") from exc
        if isinstance(body, dict) and isinstance(body.get("spec"), str):
            login = body.get("login") if isinstance(body.get("login"), str) else None
            if body.get("lang") == "en":
                _body_lang[id(request)] = "en"
            return body["spec"].encode("utf-8"), str(body.get("filename") or ""), login
        if isinstance(body, dict) and ("openapi" in body or "swagger" in body):
            return rohdaten, "spec.json", None  # die Spezifikation selbst wurde gepostet
        raise HTTPException(400, 'Erwartet {"spec": "<Dokument als Text>"} oder die Spezifikation selbst.')
    # text/plain, application/yaml, alles andere: Body ist das Dokument
    return rohdaten, "", None


def _aus_multipart(rohdaten: bytes, ctype: str) -> tuple[bytes, str, str | None]:
    from email.parser import BytesParser  # noqa: PLC0415
    from email.policy import HTTP  # noqa: PLC0415

    nachricht = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + ctype.encode("latin-1", "ignore") + b"\r\nMIME-Version: 1.0\r\n\r\n" + rohdaten
    )
    login = None
    for teil in nachricht.iter_parts():
        name = teil.get_param("name", header="content-disposition")
        if name == "login":
            login = teil.get_payload(decode=True).decode("utf-8", "ignore").strip() or None
    for teil in nachricht.iter_parts():
        name = teil.get_param("name", header="content-disposition")
        if name in ("file", "spec"):
            return teil.get_payload(decode=True) or b"", str(teil.get_filename() or ""), login
    raise HTTPException(400, "Kein Feld „file“ im Upload.")


def _client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unbekannt"


def _antwort(nutzlast: dict[str, Any]) -> dict[str, Any]:
    r, sc = nutzlast["result"], nutzlast["score"]
    findings = r["findings"]
    return {
        "tool": {"name": "oas-audit", "version": __version__},
        "source": {"hash": r["spec_hash"], "spec_version": r["spec_version"],
                   "title": r["title"], "endpoint_count": r["endpoint_count"]},
        "summary": {
            "grade_design": sc["design"]["letter"],
            "grade_hygiene": sc["hygiene"]["letter"],
            # Herleitung je Dimension, damit das UI erklären kann, WIE die Note
            # zustande kam: die rechnerische Note vor Deckeln (``uncapped``) und
            # die Zahl der bewertenden (belegten) Befunde. Additiv — die flachen
            # ``grade_*``-Felder bleiben für Bestandskonsumenten erhalten.
            "grades": {
                "design": {
                    "letter": sc["design"]["letter"],
                    "uncapped": sc["design"]["uncapped"],
                    "finding_count": sc["design"]["finding_count"],
                },
                "hygiene": {
                    "letter": sc["hygiene"]["letter"],
                    "uncapped": sc["hygiene"]["uncapped"],
                    "finding_count": sc["hygiene"]["finding_count"],
                },
            },
            "caps": sc["design"]["caps"] + sc["hygiene"]["caps"],
            "counts": {
                "belegt": sum(1 for f in findings if f["confidence"] == "belegt" and f["aggregate_count"] is None),
                "wahrscheinlich": sum(1 for f in findings if f["confidence"] == "wahrscheinlich" and f["aggregate_count"] is None),
                "aggregat": sum(1 for f in findings if f["aggregate_count"] is not None),
            },
            "runtime_gap_count": len(r["runtime_gaps"]),
            "catalog_count": len(r["catalog"]),
            "note": TESTREIFE_SATZ,
        },
        "findings": findings,
        "catalog": r["catalog"],
        "blind_spots": r["blind_spots"],
        "runtime_gaps": r["runtime_gaps"],
    }
