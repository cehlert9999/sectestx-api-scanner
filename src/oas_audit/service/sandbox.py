"""Analyse in einem eigenen Arbeitsprozess mit harten Grenzen.

Ein Mechanismus für alle Ressourcenbomben: YAML-Alias-Expansion, ``$ref``-
Explosion, pathologische Regex-Läufe. Der Arbeitsprozess bekommt
Speicher-, CPU- und Dateigrößenlimit (letzteres 0 — er darf nichts
schreiben) und wird nach Ablauf der Wanduhr beendet.

Absichtlich ``multiprocessing`` statt ``subprocess``: es gibt keinen
Shell-Aufruf und kein Kommando, das man manipulieren könnte — nur eine
Python-Funktion in einem Kindprozess.
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
from typing import Any

from oas_audit.service.loader import SpecError, load_spec_untrusted


class ScanTimeout(RuntimeError):
    pass


class ScanCrashed(RuntimeError):
    pass


def _limits(memory: int, cpu: int) -> None:
    try:
        import resource  # noqa: PLC0415 — nur unter Unix vorhanden
    except ImportError:  # pragma: no cover
        return
    for res, wert in ((resource.RLIMIT_CPU, (cpu, cpu + 1)),
                      (resource.RLIMIT_FSIZE, (0, 0)),
                      (resource.RLIMIT_AS, (memory, memory))):
        # RLIMIT_AS wird z.B. auf macOS nicht angenommen — dann ohne dieses eine Limit.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(res, wert)


def _worker(conn, data: bytes, hint: str, login: str | None, memory: int, cpu: int, lang: str = "de") -> None:
    _limits(memory, cpu)
    try:
        from oas_audit.audit import audit  # noqa: PLC0415 — erst nach dem Setzen der Limits
        from oas_audit.scoring import score  # noqa: PLC0415

        spec = load_spec_untrusted(data, hint=hint)
        result = audit(spec, login_endpoint=login, lang="en" if lang == "en" else "de")
        conn.send(("ok", {"result": result.model_dump(mode="json"),
                          "score": score(result).model_dump(mode="json")}))
    except SpecError as exc:
        conn.send(("spec_error", str(exc)))
    except ValueError as exc:  # z.B. nicht unterstützte Version aus dem Parser
        conn.send(("spec_error", str(exc)))
    except MemoryError:
        conn.send(("spec_error", "Dokument zu groß für die Verarbeitung."))
    except RecursionError:
        conn.send(("spec_error", "Dokument zu tief verschachtelt."))
    except Exception as exc:  # noqa: BLE001 — Typ nach außen, nie der Inhalt
        conn.send(("crash", type(exc).__name__))
    finally:
        conn.close()


def run_isolated(data: bytes, *, hint: str = "", login: str | None = None, lang: str = "de",
                 memory: int = 512 * 1024 * 1024, cpu: int = 5, wall: float = 8.0) -> dict[str, Any]:
    """Führt die Analyse aus. Wirft SpecError, ScanTimeout oder ScanCrashed."""
    ctx = mp.get_context("spawn")
    eltern, kind = ctx.Pipe(duplex=False)
    proz = ctx.Process(target=_worker, args=(kind, data, hint, login, memory, cpu, lang), daemon=True)
    proz.start()
    kind.close()
    try:
        if not eltern.poll(wall):
            raise ScanTimeout(f"Analyse nach {wall:.0f} s abgebrochen.")
        try:
            status, nutzlast = eltern.recv()
        except (EOFError, OSError) as exc:
            # Ohne Nachricht gestorben: fast immer das Speicher- oder CPU-Limit.
            raise SpecError("Dokument zu groß oder zu komplex für die Verarbeitung.") from exc
    finally:
        eltern.close()
        proz.join(0.5)
        if proz.is_alive():
            proz.kill()
            proz.join(1.0)
    if status == "ok":
        return nutzlast
    if status == "spec_error":
        raise SpecError(nutzlast)
    raise ScanCrashed(str(nutzlast))
