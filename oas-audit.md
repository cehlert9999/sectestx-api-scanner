# oas-audit

Statische OWASP-Security-Analyse für OpenAPI-Spezifikationen — **ohne einen einzigen
Request gegen die beschriebene API**.

`oas-audit` liest eine Swagger-2.0- oder OpenAPI-3.x-Spezifikation und beantwortet zwei
Fragen:

1. **Was steht in diesem Dokument, das sicherheitsrelevant ist?**
2. **Was wäre daran zu testen?**

## Was es ausdrücklich nicht tut

Es sendet keine Requests. Alles, was dieses Werkzeug ausgibt, ist aus dem Dokument
abgeleitet — es ist damit notwendigerweise eine Aussage über die *Spezifikation*, nicht
über das tatsächliche Verhalten der Schnittstelle.

Der Unterschied ist nicht kosmetisch. Eine Spezifikation kann
`additionalProperties: false` deklarieren, während die Implementierung beliebige Felder
annimmt. Sie kann ein Bearer-Token verlangen, während der Server ein `alg: none`-Token
akzeptiert. Solche Abweichungen sind aus dem Dokument prinzipiell nicht erkennbar, und
kein Werkzeug dieser Art kann sie finden.

Deshalb trägt jeder Befund einen von drei Zuständen:

| Zustand | Bedeutung |
|---|---|
| **belegt** | Direkt aus der Spezifikation ablesbar, mit Zitat und Fundstelle |
| **wahrscheinlich** | Starke Indizien im Dokument, aber nicht abschließend entscheidbar |
| **nur zur Laufzeit prüfbar** | Namentlich ausgewiesen, nicht bewertet |

Dazu wird die **Abdeckungsquote** ausgewiesen: wie viele der typischen Risikoklassen aus
diesem Dokument überhaupt beurteilbar sind. Gegen eine Referenz-API mit 22 dokumentierten
Schwachstellen sind es 12 — rund 55 %.

## Verwendung

```bash
oas-audit openapi.yaml            # Textbericht
oas-audit openapi.yaml --json     # maschinenlesbar (Befunde, Blindstellen, Noten, Prüfsatz)
oas-audit openapi.yaml --catalog  # nur den Prüfsatz als Markdown (--lang en für Englisch)
oas-audit --checks                # alle Regelkennungen
```

Der Bericht hat fünf Abschnitte: **belegt** (bewertet), **wahrscheinlich**
(Prüfaufträge, nicht bewertet), **Stil-Beobachtungen** (gesammelt statt je
Endpunkt), **Blindstellen** (Strukturen, die nicht ausgewertet wurden — etwa
`additionalOperations` oder die `QUERY`-Methode aus OpenAPI 3.2) und
**nur zur Laufzeit prüfbar**.

### Der Prüfsatz

Das eigentliche Produkt: aus Klassifikation und Befunden abgeleitete Testfälle im
Klartext — je Operation oder je Ressource, mit Vorbedingung, Schritten, sicherem
Sollverhalten und dem Signal, an dem man einen Befund erkennt. Deterministisch,
zweisprachig, **ohne ausführbare Payloads**: eine Verteidigungs-Checkliste, kein
Angriffsplan. Jeder Fall trägt die OWASP-Zuordnung und den Bezug zu ISO/IEC 27001
8.29 und § 30 Abs. 2 Nr. 5 BSIG. Priorität 1 sind belegte Befunde, Objektzugriffe auf
sensible Daten und administrative Funktionen.

### Zwei Noten, keine Prozente

Ein heuristisches Urteil aus einem Dokument darf keine Prozentpunkt-Genauigkeit
behaupten. Deshalb zwei Schulnoten A–F, getrennt nach **Sicherheitsdesign** und
**Spezifikationshygiene** — damit saubere Schemata eine fehlende
Authentifizierung nicht wegmitteln. Einzelne Befunde deckeln die Note (eine
dokumentierte Offenlegung sensibler Daten ohne Authentifizierung: höchstens F),
und jeder Deckel steht mit Begründung im Bericht.

> Eine gute Note bedeutet, dass die Spezifikation testreif ist —
> nicht, dass die Schnittstelle sicher ist.

### Regelkatalog

Rund 30 Regeln, bewusst nicht mehr. Jede trägt OWASP-Zuordnung, Fundstelle
(JSON-Pointer) und ihren Zustand; jede hat einen Negativtest — ohne den keine
Aufnahme. Regeln, die bei mehr als der Hälfte der Endpunkte anschlagen, werden
zu einem Aggregat zusammengefasst: was fast überall zutrifft, ist ein Stil,
keine Schwachstelle. Es werden ausschließlich Feldnamen zitiert, nie
Beispielwerte.

Gemessen an der Referenz-API mit 22 dokumentierten Schwachstellen:
5 sicher belegt, 7 als Prüfauftrag genannt, 10 als Laufzeitlücke ausgewiesen
(`tests/fixtures/gp-service-demo.erwartung.json`). Eine bewusst saubere
Spezifikation (`tests/fixtures/clean-api.yaml`) muss A/A ohne belegten Befund
ergeben — das ist die Falschmeldungsprobe.

### Als Dienst

```bash
pip install 'oas-audit[service]'
OAS_AUDIT_ALLOWED_ORIGINS=https://sectestx.leanofy.de python -m oas_audit.service
curl -s -X POST localhost:6010/api/v1/scan -H 'content-type: application/yaml' --data-binary @openapi.yaml
```

Der Dienst hält die Spezifikation nur im Arbeitsspeicher, schreibt nichts auf
Platte, lädt nichts per URL nach und lässt jede Analyse in einem eigenen
Prozess mit Speicher-, CPU- und Zeitlimit laufen. Ratenbegrenzung und
CORS-Ursprünge sind konfigurierbar (`deploy/env.example`); ein AST-Test
(`tests/test_free_isolation.py`) sichert ab, dass der Dienst nichts aus dem
Pro-Produkt importiert. Betrieb: `deploy/README.md`. Was mit einer
hochgeladenen Spezifikation passiert und welcher Test das belegt: `TRANSPARENZ.md`. Wer nicht hochladen darf,
betreibt dasselbe Image intern (`deploy/Dockerfile`).

### Als Bibliothek

```python
from oas_audit import audit, load_spec, score

result = audit(load_spec("openapi.yaml"))
grades = score(result)
print(grades.design.letter, grades.hygiene.letter)
for f in result.belegt:
    print(f.check_id, f.method, f.subject, f.evidence[0].pointer)
```

Parser und Klassifikator sind auch einzeln nutzbar:

```python
from oas_audit import OpenAPIParser, classify_all, load_spec

spec = load_spec("openapi.yaml")          # Datei oder URL (URL braucht das Extra "fetch")
endpoints = OpenAPIParser(spec).parse()
classified = classify_all(endpoints)

for ep in classified:
    if ep.endpoint.has_alternative_auth:
        print(f"{ep.endpoint.method.value} {ep.endpoint.path}: "
              f"{len(ep.endpoint.security_alternatives)} alternative Auth-Wege "
              f"— das schwächste Glied entscheidet")
```

### ODER statt UND

Ein häufiges und folgenreiches Missverständnis der Spezifikation:

```yaml
security:                 # A ODER B genügt
  - ApiKey: []
  - BearerToken: []

security:                 # A UND B nötig
  - ApiKey: []
    BearerToken: []
```

Hinter einem API-Gateway ist die erste Variante fast immer ein Fehler, wo die zweite
gemeint war. `oas-audit` erhält diese Struktur in `Endpoint.security_alternatives` — die
flache Liste `Endpoint.security` beantwortet nur noch „braucht der Endpoint überhaupt
Auth?".

## Installation

```bash
pip install oas-audit          # Kern, kein Netzwerk
pip install 'oas-audit[fetch]' # zusätzlich Spec-Laden per URL
```

## Lizenz

Apache-2.0. Siehe `LICENSE` und `NOTICE`.

Die Zuordnung der Prüfregeln zu den OWASP API Security Top 10 orientiert sich an der
Veröffentlichung der [OWASP Foundation](https://owasp.org/API-Security/) (CC BY-SA 4.0);
Regeltexte und Implementierung sind eigenständig formuliert.
