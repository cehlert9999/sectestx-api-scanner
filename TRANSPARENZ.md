# Transparenz: Was mit einer hochgeladenen Spezifikation passiert

Kurzfassung: **Sie wird verarbeitet und vergessen.** Nichts davon steht auf einer Platte,
in einem Log oder in einer Datenbank — und der Betreiber kann sie nicht nachträglich lesen,
weil es nichts gibt, das er lesen könnte.

| Frage | Antwort | Beleg im Quellcode |
|---|---|---|
| Wird die Spezifikation gespeichert? | Nein. Sie liegt nur im Arbeitsspeicher des Requests und wird nach der Antwort freigegeben. | `service/app.py` (`del daten`), `tests/test_keine_spuren.py::test_scan_hinterlaesst_keine_datei` |
| Kann der Arbeitsprozess sie auf Platte schreiben? | Nein, auch nicht versehentlich: Dateigrößenlimit 0 (`RLIMIT_FSIZE`). | `service/sandbox.py`, `tests/test_keine_spuren.py::test_arbeitsprozess_kann_nicht_schreiben` |
| Landet Inhalt in Logs? | Nein. Der Dienst loggt bei Abbrüchen nur den Exception-Typ, kein Access-Log, kein Body. | `tests/test_keine_spuren.py::test_logs_enthalten_keinen_dokumentinhalt`, `service/__main__.py` (`access_log=False`), `deploy/nginx.*.conf` (`access_log off`) |
| Werden Beispielwerte aus dem Dokument zurückgegeben? | Nein. Der Bericht nennt Feldnamen und Pfade, nie `example`/`default`-Werte. | `sensitive.py`, `tests/test_keine_spuren.py::test_antwort_enthaelt_keine_beispielwerte` |
| Wird eine Anfrage an die beschriebene API gesendet? | Nein, nie. Der Dienst hat keinen URL-Fetch; ein AST-Test verbietet jeden Netzwerk-Import. | `tests/test_free_isolation.py` |
| Werden IP-Adressen gespeichert? | Nur als HMAC mit täglich wechselndem Salz, im Arbeitsspeicher, für die Ratenbegrenzung. Nach 24 h weg. | `service/limits.py` |
| Wird das Ergebnis gespeichert? | Nein. Es geht signiert an den Browser zurück. Eine Speicherung entsteht erst, wenn der Nutzer einen PDF-Bericht anfordert (noch nicht verfügbar). | `service/signing.py` |
| Speichert der Browser etwas? | Nein. Kein localStorage, kein Cookie durch das Widget; die Eingabe lebt nur im Seitenzustand. | leanofy-v2 `src/components/sectestx/check/` |
| Kann ich das selbst betreiben? | Ja, mit demselben Image: `deploy/Dockerfile`. | `deploy/README.md` |

Wer der Zusage nicht trauen will, muss es nicht: Der Dienst ist quelloffen, und die Tests
oben laufen bei jeder Änderung.
