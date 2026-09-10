# sectestx API Scanner — Spezifikation des Free-Tools

*Stand: 10. September 2026 · Version oas-audit 0.2.0 · Dieses Dokument beschreibt das System, wie es
gebaut und in Betrieb ist. Tabellen mit Regeln, Vorlagen und Laufzeitlücken sind aus dem Quelltext
erzeugt; bei Abweichung gilt der Quelltext.*

---

## 1. Zweck und Positionierung

Der Free-Scanner ist der Top-of-Funnel für sectestx: ein kostenloser, anmeldefreier Dienst, der aus
einer OpenAPI- oder Swagger-Spezifikation ableitet, **was daran sicherheitsrelevant ist und was daran
zu testen wäre** — ohne einen einzigen Request an die beschriebene API.

Die Marktanalyse (September 2026) hat ergeben: der statische Spec-Score ist Commodity (42Crunch, vacuum,
Treblle, Zuplo liefern ihn gratis). Frei ist dagegen: **kein Werkzeug im Feld leitet aus einer Spec einen
lesbaren Security-Testfall-Katalog ab, keines spricht Deutsch, keines adressiert DACH-Compliance.**
Deshalb ist der **Prüfsatz** das Produkt und die Note nur die Eintrittskarte.

Die Grenze zum Pro-Produkt in einem Satz: **statisch = offen, verifiziert/ausführbar = Pro.**
Free sagt „das wäre hier zu testen, so sieht der Prüfsatz aus“. Pro sagt „das haben wir getestet, hier
ist die Evidence“.

Zwei Stufen, eine Codebasis:

| Stufe | Paket | Liest | Aussage über | Läuft |
|---|---|---|---|---|
| Öffentlicher Einstieg | `oas-audit` | OpenAPI 3.0/3.1, Swagger 2.0 | die Spezifikation | im Web und lokal |
| Vertriebswerkzeug | `wm-audit` | webMethods-API-Gateway-Export (ZIP/Verzeichnis) | die tatsächliche Gateway-Konfiguration | **nur lokal** (Export enthält Zugangsdaten) |

## 2. Zusicherungen (nicht verhandelbar)

1. **Kein Request an die beschriebene API.** Auch kein „harmloser“. Der Dienst hat keinen URL-Fetch;
   ein AST-Test verbietet jeden Netzwerk-Import (`tests/test_free_isolation.py`).
2. **Die Spezifikation wird nie gespeichert.** Nur im Arbeitsspeicher des Requests, nie auf Platte,
   nie in Logs. Nachgewiesen durch `tests/test_keine_spuren.py` (leeres Verzeichnis nach dem Scan,
   Schreibversuch des Arbeitsprozesses scheitert, Logs ohne Dokumentinhalt).
3. **Nur Feldnamen, nie Werte.** Beispielwerte aus `example`/`default` werden nicht gelesen und nicht
   zurückgegeben.
4. **Kein Sprachmodell im Free-Pfad.** Befunde und Prüfsatz sind deterministisch: gleiche Eingabe,
   gleiche Kennungen.
5. **Kein Import aus dem Pro-Produkt.** Das freie Paket ist eigenständig lauffähig; `sectestx` zieht
   `oas-audit` als Abhängigkeit, nicht umgekehrt.
6. **Keine Konformitätsbehauptung.** Zulässig ist der Bezug („unterstützt Ihre Pflichten nach § 30
   Abs. 2 Nr. 5 BSIG“), nie „NIS2-konform“ oder „DORA-Testnachweis“.

Details und Belegstellen: `TRANSPARENZ.md`.

## 3. Architektur

### 3.1 Komponenten

```
Browser (sectestx.leanofy.de/check · leanofy.de/api-sicherheit-pruefen · /en/api-security-check)
   │  React-Widget (leanofy-v2: SpecInput, ResultView, CatalogView, oasAuditClient.ts)
   │  POST https://api.sectestx.leanofy.de/api/v1/scan   {spec, filename, lang}
   ▼
Nginx (api.sectestx.leanofy.de, TLS, access_log off, 3 MB Body-Limit, X-Forwarded-For)
   ▼
FastAPI-Dienst  127.0.0.1:6010  (systemd-Unit oas-audit, gehärtet)
   ├─ Rate-Limit (IP als Tages-Hash)        service/limits.py
   ├─ streamendes Upload-Limit 2 MB         service/app.py
   ├─ Loader ohne Dateisystem, Bomben-Check service/loader.py
   └─ Arbeitsprozess je Scan (spawn)        service/sandbox.py
         └─ audit(spec) ──► Parser ─► Klassifikator ─► Regeln ─► Aggregation ─► Scoring ─► Katalog
   ▼
JSON-Antwort, HMAC-signiert — nichts wird gespeichert
```

### 3.2 Pakete und Module (`src/oas_audit`)

| Modul | Aufgabe |
|---|---|
| `parser/openapi.py` | Swagger 2.0 / OpenAPI 3.x → `Endpoint`-Liste; `$ref` per jsonref aufgelöst; JSON-Pointer je Operation; ODER/UND-Struktur der Security erhalten (`security_alternatives`) |
| `classifier.py` | regelbasiert: Operationstyp (list/read/create/update/delete/action), ID-artige Parameter, Ressourcen-Hint, Login-Endpunkt, dokumentierte Methoden je Pfad |
| `sensitive.py` | Token-Abgleich von Feldnamen (Finanz, Credential, PII); rekursiver, zyklensicherer Schema-Walker |
| `findings.py` | `Finding`, `Evidence`, `BlindSpot`, `RuntimeGap`; Aggregations-Helfer |
| `rules.py` | Regelkatalog (Dokument- und Endpunktregeln), Blindstellen, Laufzeitlücken, `AuditContext` |
| `scoring.py` | zwei Noten A–F mit Deckeln |
| `catalog.py` | Prüfsatz-Vorlagen DE/EN, Markdown-Export |
| `audit.py` | Einstieg `audit(spec, login_endpoint, lang) → AuditResult` |
| `cli.py` | `oas-audit spec.yaml [--json] [--catalog] [--lang de\|en] [--checks]` |
| `service/` | FastAPI-Dienst: `app.py`, `settings.py`, `loader.py`, `sandbox.py`, `limits.py`, `signing.py` |

`wm-audit` (`wm_audit/reader.py`, `models.py`, `rules.py`) hängt an `oas_audit.findings` und liefert
dasselbe Befund-Modell für Gateway-Exporte.

### 3.3 Datenfluss eines Scans

1. Der Browser sendet Text oder Datei (JSON, YAML, max. 2 MB) plus Einwilligung
   („Ich bin berechtigt, diese Spezifikation zu analysieren“).
2. Der Dienst prüft Rate-Limit, liest den Body streamend und bricht vor Überschreiten des Limits ab.
3. Ein Arbeitsprozess (multiprocessing, Start-Methode `spawn`) erhält die Bytes über eine Pipe, setzt
   `RLIMIT_CPU` 5 s, `RLIMIT_FSIZE` 0, `RLIMIT_AS` 512 MB (best effort) und hat 8 s Wanduhr.
4. Loader: UTF-8-Prüfung, JSON oder YAML, YAML-Alias-Bombe wird am Knotengraphen erkannt (max. 200
   Aliase, max. 2 Mio. expandierte Knoten), Tiefe max. 200, `openapi`/`swagger` muss vorhanden sein,
   `$ref` werden aufgelöst.
5. `audit()` liefert Befunde, Blindstellen, Laufzeitlücken, Prüfsatz; `score()` die Noten.
6. Die Antwort wird kanonisch serialisiert und HMAC-SHA256-signiert (`signature`). Der Dienst behält
   nichts.

## 4. Datenmodell

### 4.1 Endpoint (`models.py`)

`method`, `path`, `operation_id`, `summary`, `tags`, `path_parameters`, `query_parameters`
(Name, Schematyp), `request_schema`, `response_schemas` (Code → Schema), `deprecated`, `security`
(flach), **`security_alternatives`** (äußere Liste ODER, innere UND), `security_source`
(`operation`/`global`/`none`), **`pointer`** (JSON-Pointer, RFC 6901), `response_codes` (alle, auch
`4XX`/`default`), `request_content_types`.

`ClassifiedEndpoint` ergänzt `operation_type`, `id_like_parameter`, `resource_hint`,
`is_login_endpoint`, `documented_methods`, `paired_list_endpoint`.

### 4.2 Finding (`findings.py`)

| Feld | Bedeutung |
|---|---|
| `check_id` | stabile Regelkennung, z. B. `endpoint.unauth_write` |
| `confidence` | **belegt** (scorewirksam, mit Fundstelle) · **wahrscheinlich** (Prüfauftrag, nie bewertet) · **laufzeit** |
| `severity` | critical / high / medium / low / info |
| `owasp` | API1…API9 (OWASP API Security Top 10, 2023) |
| `scope` / `subject` / `method` | Dokument, Endpunkt oder API; Pfad, Schema-Name, Ressource |
| `reason` / `remediation` | Klartext: warum greift die Regel hier, was ist zu tun |
| `evidence[]` | `pointer` (JSON-Pointer), `excerpt` (≤ 200 Zeichen, nur Struktur), `note` |
| `aggregate_count` / `affected[]` | bei Aggregaten: Anzahl und betroffene Subjekte |
| `dimension` | `design` (Sicherheitsdesign) oder `hygiene` (Spezifikationshygiene) |
| `cap` | deckelt die Note der Dimension (z. B. `D`) |
| `id` | SHA-1 aus `check_id|method|subject`, gekürzt — stabil über Läufe |

`scores` ist wahr genau dann, wenn `confidence == belegt` (ein belegtes Aggregat zählt einmal).

### 4.3 Weitere Modelle

- **BlindSpot** (`pointer`, `what`, `why`): eine Struktur, die nicht ausgewertet wurde.
- **RuntimeGap** (`key`, `title`, `owasp`, `why`): eine statisch nicht entscheidbare Risikoklasse.
- **TestCase** (`catalog.py`): `key`, `owasp`, `priority` 1–3, `method`, `path`, `title`,
  `precondition`, `steps[]`, `expected`, `fail_signal`, `static_state`, `related_check`,
  `also_applies_to[]`, `controls[]`; `id` stabil aus `key|method|path`.
- **Score** (`scoring.py`): `design` und `hygiene` je `Grade(letter, points, uncapped, caps[])`,
  `runtime_gap_count`, `note`.

## 5. Analysepipeline

### 5.1 Parser

Unterstützt Swagger 2.0 (`securityDefinitions`, `host`/`schemes`/`basePath`, `formData`-Dateien →
Binärschema) und OpenAPI 3.0/3.1. Andere Versionen werden abgelehnt (`ValueError` → 422). Nicht-
Standard-Methoden (OpenAPI 3.2 `additionalOperations`, `query`) werden **nicht** als Operation
gelesen, sondern als Blindstelle gemeldet (siehe 5.5).

### 5.2 Klassifikator

ID-artige Parameter über Namensmuster (`_id`, `uuid`, `number`, `code`) und Typ-Hinweise (`uuid`,
`integer`), mit Deny-Liste für Paginierungs- und Steuerparameter (`limit`, `offset`, `sort`, …).
Ressourcen-Hint aus dem Pfad (überspringt `api`, `vN`, Aktions-Segmente wie `by-number`).

### 5.3 Regeln

Drei Grundsätze: kein Befund ohne Fundstelle; nur Feldnamen, nie Werte; was fast überall zutrifft,
ist ein Stil, keine Schwachstelle.

**Aggregation:** Eine Regel, die bei **mehr als 50 %** der Endpunkte anschlägt, wird zu einem Befund
zusammengefasst (`aggregate_count`, `affected[]`). Vier Regeln sind von vornherein als Aggregat
angelegt. Ein belegtes Aggregat behält seine Schwere und zählt einmal; ein wahrscheinliches Aggregat
wird zur Information.

**Bündelung:** Sensible Antwortfelder werden je *Schema* gemeldet (nicht je Operation), Objektzugriffe
je *Ressource*, administrative Pfade je *Präfix*.

**Ausnahmen:** Auth-Flow-Pfade (`login`, `token`, `register`, `oauth`, …) lösen keine
Unauthentifiziert-Regeln aus; Login-Antworten dürfen `token`-Felder liefern.

| Regel | OWASP | Schwere | Zustand | Dimension | Deckel | Aggregat | Titel |
|---|---|---|---|---|---|---|---|
| `endpoint.admin_path` | API5 | CRITICAL/HIGH | BELEGT/WAHRSCHEINLICH | design | F | ab >50 % | Administrative Funktion ohne Authentifizierung |
| `endpoint.credentials_in_query` | API8 | HIGH | BELEGT | design | - | ab >50 % | Zugangsdaten als Query-Parameter |
| `endpoint.debug_path` | API8 | HIGH/MEDIUM | BELEGT/WAHRSCHEINLICH | design | D | ab >50 % | Diagnose-Endpunkt in der öffentlichen Schnittstelle |
| `endpoint.list_without_pagination` | API4 | MEDIUM | WAHRSCHEINLICH | design | - | ab >50 % | Listenoperation ohne Paginierungsparameter |
| `endpoint.no_error_responses` | API8 | LOW | WAHRSCHEINLICH | hygiene | - | immer | Authentifizierte Operationen ohne dokumentierte 401/403-Antwort |
| `endpoint.object_level_access` | API1 | HIGH / MEDIUM | WAHRSCHEINLICH | design | - | ab >50 % | Objektzugriff per ID — Objektberechtigung ist nicht dokumentiert |
| `endpoint.sequential_integer_id` | API1 | MEDIUM | WAHRSCHEINLICH | design | - | ab >50 % | Objekt-ID ist eine ganze Zahl |
| `endpoint.unauth_id_read` | API1 | HIGH | BELEGT | design | - | ab >50 % | Objektzugriff per ID ohne Authentifizierung |
| `endpoint.unauth_sensitive_response` | API3 | CRITICAL | BELEGT | design | F | ab >50 % | Sensible Daten ohne Authentifizierung abrufbar |
| `endpoint.unauth_write` | API5 | HIGH | BELEGT | design | D | ab >50 % | Schreibende Operation ohne Authentifizierung |
| `endpoint.unbounded_upload` | API4 | MEDIUM | WAHRSCHEINLICH | design | - | ab >50 % | Datei-Upload ohne dokumentierte Größenbegrenzung |
| `endpoint.write_without_scope` | API5 | MEDIUM | WAHRSCHEINLICH | design | - | immer | Schreibende Operationen ohne dokumentierte Rolle oder Scope |
| `gateway.wm_detected` | API9 | INFO | BELEGT | design | - | ab >50 % | Merkmale eines webMethods API Gateway |
| `path.crud_method_gap` | API9 | LOW | WAHRSCHEINLICH | hygiene | - | ab >50 % | Objektpfad nur lesend dokumentiert |
| `schema.additional_properties_open` | API3 | LOW | WAHRSCHEINLICH | design | - | immer | Schreibschemata ohne additionalProperties: false |
| `schema.credential_in_response` | API3 | CRITICAL | BELEGT | design | D | ab >50 % | Geheimnis im Antwort-Schema |
| `schema.no_constraints` | API4 | LOW | WAHRSCHEINLICH | hygiene | - | immer | Request-Schemata ohne Längenbegrenzung |
| `schema.sensitive_in_response` | API3 | HIGH / MEDIUM | WAHRSCHEINLICH | design | - | ab >50 % | Finanz- oder personenbezogene Daten im Antwort-Schema |
| `spec.api_key_in_query` | API8 | MEDIUM | BELEGT | design | - | ab >50 % | API-Key wird als Query-Parameter übertragen |
| `spec.basic_auth` | API2 | MEDIUM | BELEGT | design | - | ab >50 % | HTTP Basic Authentication |
| `spec.deprecated_no_sunset` | API9 | LOW | BELEGT | hygiene | - | ab >50 % | Als veraltet markiert, aber ohne Abschaltdatum |
| `spec.http_server` | API8 | HIGH | BELEGT | design | - | ab >50 % | Server-URL ohne TLS |
| `spec.no_global_security` | API2 | MEDIUM | BELEGT | hygiene | - | ab >50 % | Kein globales security-Requirement |
| `spec.no_security_schemes` | API2 | HIGH | BELEGT | design | D | ab >50 % | Kein Authentifizierungsverfahren definiert |
| `spec.nonprod_server` | API9 | MEDIUM | BELEGT/WAHRSCHEINLICH | hygiene | - | ab >50 % | Server-URL zeigt auf ein lokales oder privates Ziel |
| `spec.oauth2_implicit` | API2 | MEDIUM | BELEGT | design | - | ab >50 % | OAuth2 Implicit Flow |
| `spec.oauth2_no_scopes` | API5 | LOW | BELEGT | design | - | ab >50 % | OAuth2 ohne Scopes |
| `spec.security_or_semantics` | API2 | HIGH | BELEGT | design | - | ab >50 % | Globales security-Requirement akzeptiert alternative Verfahren (ODER) |
| `spec.version_sprawl` | API9 | MEDIUM | BELEGT | design | - | ab >50 % | Mehrere API-Versionen parallel dokumentiert |

### 5.4 Erkennung sensibler Felder (`sensitive.py`)

Feldnamen werden in Tokens zerlegt (`creditCardNumber` → `credit, card, number`; `vat_id` →
`vat, id`) und gegen Token-Folgen abgeglichen, damit `bic` nicht `public` trifft. Drei Kategorien:

- **Finanz:** iban, bic, swift, kontonummer, account number, credit card, card number, cvv/cvc, ssn,
  sozialversicherungsnummer, tax id, vat id, steuer id, passport, national id, …
- **Credential:** password/passwort/kennwort, secret, private key, api key, access key, token,
  session id, otp, security answer, recovery code
- **PII:** email, phone/mobile/telefon, date of birth/geburtsdatum, salary/gehalt/income,
  credit score/schufa, internal notes, religion, ethnicity, gender, nationality, street/strasse

Nie gelesen: `example`, `default`, `enum`-Werte.

### 5.5 Blindstellen

Namentlich ausgewiesen, nie als „geprüft“ gemeldet: `additionalOperations`, `query`-Methode,
Parameter mit unbekanntem `in` (z. B. `querystring`), Antworten nur mit `itemSchema`, `callbacks`,
`webhooks`, unbekannte Schlüssel im Path-Item, OpenAPI-Version > 3.1.

### 5.6 Laufzeitlücken

Zwölf Risikoklassen, die aus einem Dokument prinzipiell nicht folgen. Sie werden gezählt und benannt,
nie bewertet — die Kennzahl neben der Note.

| Schlüssel | OWASP | Frage | Warum statisch nicht entscheidbar |
|---|---|---|---|
| `object_authorization` | API1 | Erreicht ein Aufrufer fremde Objekte? | Objektberechtigung liegt im Backend und braucht zwei Identitäten. |
| `jwt_algorithm` | API2 | Wird ein unsigniertes Token (alg: none) abgewiesen? | Die Spezifikation nennt „bearer“, nicht die Prüflogik dahinter. |
| `jwt_expiry` | API2 | Wird das Ablaufdatum eines Tokens geprüft? | Reines Laufzeitverhalten der Token-Validierung. |
| `api_key_verification` | API2 | Wird ein erfundener API-Key abgewiesen? | Ob das Gateway den Schlüssel gegen ein Register prüft, steht nicht im Dokument. |
| `trust_header` | API2 | Lässt sich ein Trust-Header des Gateways fälschen? | Hängt davon ab, ob das Backend Header aus Client-Anfragen filtert. |
| `mass_assignment` | API3 | Übernimmt das Backend nicht dokumentierte Felder? | Ein Schema mit additionalProperties: false ist ein Versprechen, keine Prüfung. |
| `role_enforcement` | API5 | Wird die Rollenprüfung durchgesetzt? | Das Dokument nennt bestenfalls Scopes — ob sie greifen, zeigt erst ein Aufruf. |
| `rate_limit` | API4 | Greift ein Rate-Limit? | Ein dokumentierter 429 belegt nicht, dass er je gesendet wird. |
| `security_headers` | API8 | Werden Security-Header in Antworten gesetzt? | Antwort-Header sind nicht Teil einer OpenAPI-Beschreibung. |
| `cors` | API8 | Wie verhält sich CORS tatsächlich? | Erst eine Preflight-Anfrage zeigt die wirksame Regel. |
| `error_disclosure` | API8 | Enthalten Fehlerantworten Stack-Traces oder Versionen? | Fehlerformate stehen selten im Dokument und weichen im Betrieb oft davon ab. |
| `undocumented_endpoints` | API9 | Gibt es Endpunkte außerhalb des Dokuments? | Was nicht dokumentiert ist, kann kein Dokument zeigen — Swagger-UI, Debug-Routen, alte Versionen. |

## 6. Scoring

Zwei Schulnoten A–F, getrennt nach **Sicherheitsdesign** und **Spezifikationshygiene**, damit saubere
Schemata eine fehlende Authentifizierung nicht wegmitteln. Kein Prozentwert.

| Schwere | Punkte |
|---|---|
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |
| info | 0 |

Nur belegte Befunde zählen. Note aus Punkten: **A** = 0, **B** ≤ 10, **C** ≤ 30, **D** ≤ 60, sonst **F**.
Danach Deckel: ein Befund mit `cap` begrenzt die Note der Dimension auf diesen Buchstaben, solange er
besteht (z. B. sensible Daten ohne Authentifizierung → höchstens F; schreibende Operation ohne
Authentifizierung → höchstens D). Jeder Deckel wird mit Grund ausgewiesen.

Subjekt der Note ist die Spezifikation: *„Eine gute Note bedeutet, dass die Spezifikation testreif ist —
nicht, dass die Schnittstelle sicher ist.“* Dieser Satz steht in jeder Antwort.

## 7. Prüfsatz (Testfall-Katalog)

Deterministische Vorlagen, aus Klassifikation und Befunden abgeleitet. Jeder Testfall nennt
Vorbedingung, Schritte, das sichere Sollverhalten und das Signal, an dem man einen Befund erkennt.
**Ohne ausführbare Payloads** — ein Test (`test_keine_ausfuehrbaren_payloads`) verbietet
Angriffsstrings. Sprache DE oder EN, IDs sprachunabhängig.

Prioritäten: **1** zuerst prüfen (belegte Befunde bestätigen, Objektzugriff auf sensible Daten,
administrative Funktionen, ODER-Verknüpfung, Gateway), **2** je Operation/Pfad, **3** einmal je API.

`static_state` je Fall: **belegt** (bestätigt einen dokumentierten Befund), **wahrscheinlich**
(entscheidet einen Prüfauftrag), **laufzeit** (nur hier prüfbar).

Bündelung: Authentifizierung, BOLA, Schreibrechte und Mass Assignment je *Pfad* (Methoden in
`also_applies_to`), Property-Level je *Schema*, Admin je *Präfix*. Ergebnis für die Demo-API:
80 Testfälle für 38 Operationen; Obergrenze im Test: 2 × Operationen + 12.

Control-Mapping je Fall: OWASP API Security Top 10 (2023), ISO/IEC 27001:2022 8.29, § 30 Abs. 2
Nr. 5 BSIG. Der Katalog erfüllt inhaltlich 8.29 („dokumentierter Testplan mit erwarteten Ergebnissen“).

| Vorlage | OWASP | Prio | Titel (DE) | Statischer Bezug |
|---|---|---|---|---|
| `api4.rate_limit` | API4 | 3 | Rate-Limit greift | – |
| `api8.cors` | API8 | 3 | CORS erlaubt nur bekannte Ursprünge | – |
| `api8.security_headers` | API8 | 3 | Security-Header sind gesetzt | – |
| `api8.error_disclosure` | API8 | 3 | Fehlerantworten verraten keine Interna | – |
| `api9.discovery` | API9 | 3 | Dokumentation und Diagnose-Endpunkte sind nicht öffentlich | – |
| `confirm.unauthenticated` | ? | 1 | Dokumentierte Erreichbarkeit ohne Authentifizierung bestätigen | `?` |
| `auth.enforced` | API2 | 2 | Authentifizierung wird durchgesetzt | – |
| `auth.jwt_unsigned` | API2 | 1 | Unsigniertes oder umsigniertes Token wird abgewiesen | `None` |
| `auth.apikey_query` | API8 | 2 | API-Key im Query-String landet in Logs | `spec.api_key_in_query` |
| `bola.cross_user` | API1 | 1 / 2 | Fremdes Objekt per ID anfordern (BOLA) | `endpoint.object_level_access` |
| `bfla.admin_as_user` | API5 | 1 | Administrative Funktion mit gewöhnlichem Benutzer aufrufen | `endpoint.admin_path` |
| `bfla.write_least_privilege` | API5 | 2 | Schreibende Operation mit minimal berechtigtem Konto | `endpoint.write_without_scope` |
| `bopla.response_fields` | API3 | 2 / 3 | Antwort enthält nur die Felder, die die Rolle sehen darf | `schema.sensitive_in_response` |
| `bopla.mass_assignment` | API3 | 2 | Nicht dokumentiertes Feld wird ignoriert oder abgewiesen (Mass Assignment) | `schema.additional_properties_open` |
| `api4.list_bounded` | API4 | 2 | Listenantwort ist serverseitig begrenzt | `endpoint.list_without_pagination` |
| `api4.upload_bounded` | API4 | 2 | Upload-Größe wird begrenzt | `endpoint.unbounded_upload` |
| `api4.input_length` | API4 | 3 | Übergroße Eingaben werden sauber abgewiesen | `schema.no_constraints` |
| `api8.tls_only` | API8 | 2 | HTTP wird nicht bedient | `spec.http_server` |
| `api9.old_versions` | API9 | 2 | Ältere API-Versionen haben denselben Sicherheitsstand | `spec.version_sprawl` |
| `api9.undocumented_methods` | API9 | 3 | Nicht dokumentierte Methoden werden abgewiesen | `path.crud_method_gap` |
| `gateway.key_without_user` | API2 | 1 | API-Key ohne Benutzer-Token genügt nicht | `spec.security_or_semantics` |
| `gateway.trust_header` | API2 | 1 | Trust-Header des Gateways lässt sich nicht fälschen | – |
| `auth.alternatives` | API2 | 1 | Jedes alternative Verfahren einzeln prüfen (ODER-Verknüpfung) | `spec.security_or_semantics` |
| `bola.enumeration` | API1 | 2 | IDs sind durchprobierbar | `endpoint.sequential_integer_id` |

## 8. Dienst-API

Basis: `https://api.sectestx.leanofy.de`. Kein Docs-UI (`/docs` → 404), OpenAPI unter
`/api/v1/openapi.json`. Alle Antworten `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.

| Methode, Pfad | Zweck |
|---|---|
| `GET /healthz` | `{status, version}` |
| `GET /api/v1/checks` | alle Regelkennungen und Laufzeitlücken (speist Regel-Seiten) |
| `POST /api/v1/scan` | die Analyse |
| `POST /api/v1/report` | Signaturprüfung; liefert 501, bis der PDF-Bericht (v1.1) verfügbar ist |

**Request an `/scan`** — eine von drei Formen:
- `application/json` mit `{"spec": "<Dokument als Text>", "filename": "…", "lang": "de|en", "login": "/auth/login"}`
- `application/json`, dessen Body selbst die Spezifikation ist (`openapi`/`swagger` auf oberster Ebene)
- `multipart/form-data` mit Feld `file` (optional `login`), oder ein beliebiger Text-/YAML-Body

**Response 200:**

```json
{
  "tool": {"name": "oas-audit", "version": "0.2.0"},
  "source": {"hash": "…", "spec_version": "3.1.0", "title": "…", "endpoint_count": 38},
  "summary": {"grade_design": "F", "grade_hygiene": "B", "caps": [...],
              "counts": {"belegt": 11, "wahrscheinlich": 18, "aggregat": 4},
              "runtime_gap_count": 12, "catalog_count": 80, "note": "Eine gute Note …"},
  "findings": [...], "catalog": [...], "blind_spots": [...], "runtime_gaps": [...],
  "signature": "<hmac-sha256 hex>"
}
```

**Fehler:** 400 (Anfrageformat), 413 (> 2 MB, streamend geprüft, auch ohne Content-Length),
422 (Dokument nicht lesbar: leer, kein Objekt, keine Spezifikation, Version nicht unterstützt,
Alias-Bombe, zu tief, unauflösbare Referenz, Zeitlimit, zu groß für die Verarbeitung),
429 (Rate-Limit, mit `Retry-After`), 500 (Arbeitsprozess mit unbekannter Ausnahme; nur Typname im Log).

**Limits (Umgebungsvariablen, `deploy/env.example`):** 5 Scans/h und 20/Tag je IP, 500/Tag global,
4 parallele Scans, 2 MB Upload, Arbeitsprozess 512 MB / 5 s CPU / 8 s Wanduhr. CORS nur für die
gelisteten Ursprünge (`OAS_AUDIT_ALLOWED_ORIGINS`). `X-Forwarded-For` nur mit `OAS_AUDIT_TRUST_PROXY=1`.

## 9. CLI

```
oas-audit spec.yaml            Textbericht: Noten, belegt / wahrscheinlich / Stil, Blindstellen, Laufzeitlücken
oas-audit spec.yaml --json     vollständiges Ergebnis als JSON
oas-audit spec.yaml --catalog  Prüfsatz als Markdown (--lang en für Englisch)
oas-audit --checks             Regelkennungen
```

Die CLI liest Dateien und (mit Extra `fetch`) URLs — sie ist ein lokales Werkzeug; der Dienst nutzt
sie bewusst nicht (kein Dateipfad-Loader im Dienst, per AST-Test gesichert).

## 10. Frontend (leanofy-v2)

| Seite | Route | Shell |
|---|---|---|
| Check-Seite | `sectestx.leanofy.de/check` (= `/sectestx/check`) | sectestx-Chrome (dunkel), Header-Link „Kostenloser Check“, Hero-Einstieg |
| SEO-Seite DE | `leanofy.de/api-sicherheit-pruefen` | leanofy-Shell, Tools-Übersicht, Footer |
| SEO-Seite EN | `leanofy.de/en/api-security-check` | dito; Prüfsatz auf Englisch, Befundtexte derzeit Deutsch |

Widget (`src/components/sectestx/check/`): `SpecInput` (Einfügen, Datei, Drag-and-drop, Beispiel,
Größenanzeige, Einwilligungs-Checkbox, Datenschutzhinweis, Quellcode-Link), `ResultView` (zwei
Noten-Kacheln mit gebündelten Deckeln, Kachel „statisch beurteilbar“, aufgeklappte Legende, Blöcke
Belegt / Prüfaufträge / Prüfsatz / Stil / Blindstellen / Laufzeit, Pro-CTA), `CatalogView` (Filter nach
Priorität und OWASP, aufklappbare Fälle, Markdown kopieren oder als `.md` herunterladen).
Client `src/lib/oasAuditClient.ts` (Typen, `scanSpec`, Fehler-Mapping). Kein localStorage, kein Cookie.

Prerender: alle drei Routen werden zu statischem HTML gerendert (`scripts/prerender.js`,
Canonical-Overrides für die Subdomain), die `.htaccess` liefert prerenderte Unterseiten der Subdomain
aus. Die Content-Security-Policy muss `connect-src https://api.sectestx.leanofy.de` enthalten.

## 11. Betrieb

| Komponente | Wo | Wie |
|---|---|---|
| Frontend | All-Inkl (leanofy.de, Subdomain sectestx.leanofy.de) | Push auf `leanofy-v2` master → Jenkins (SCM-Polling, 5 min) → Build + Prerender → rsync |
| Backend | Hetzner-Server, `api.sectestx.leanofy.de` | rsync von `code/oas-audit` nach `/opt/oas-audit/src`, venv, `systemd`-Unit `oas-audit` (NoNewPrivileges, ProtectSystem=strict, MemoryMax 1G), Nginx mit Let's Encrypt, `access_log off` |
| Secret | `/etc/oas-audit/env` (chmod 640) | `OAS_AUDIT_SECRET` für Signaturen und IP-Hashes |
| Öffentliches Repo | github.com/cehlert9999/sectestx-api-scanner | `code/scripts/publish-free-tool.sh` (Snapshot, Server-IP maskiert), GitHub-Actions-CI |

Update des Backends: rsync, `pip install /opt/oas-audit/src[service]`, `systemctl restart oas-audit`,
`curl /healthz`. Selbst-Hosting: `deploy/Dockerfile` (non-root), `deploy/README.md`.

## 12. Qualitätssicherung

| Nachweis | Datei | Inhalt |
|---|---|---|
| Ground Truth | `tests/fixtures/gp-service-demo.erwartung.json`, `test_rules.py` | 22 dokumentierte Bugs der Demo-API: **5 certain** (belegt gefunden), **7 candidate** (als Prüfauftrag genannt), **10 impossible** (als Laufzeitlücke ausgewiesen) → 12/22 statisch, 55 % |
| Falschmeldungsprobe | `tests/fixtures/clean-api.yaml` | muss A/A ohne belegten Befund und ohne Hinweis über „mittel“ ergeben |
| Negativtest je Regel | `test_rules.py::FAELLE` + Vollständigkeitswächter | jede Regel greift, wo sie soll, und schweigt sonst; keine Regel ohne Negativtest |
| OAS 3.2 | `tests/fixtures/oas32-constructs.yaml` | alle nicht ausgewerteten Konstrukte erscheinen als Blindstelle |
| Katalog | `test_catalog.py` | Ground-Truth-Abdeckung, Determinismus, keine Payloads, Lesbarkeitsgrenze, EN |
| Dienst | `test_service.py` | Alias-Bombe, 10 000 Ebenen, zyklische Referenz, 413 (auch ohne Content-Length), 429 ab dem 6. Scan, manipulierte Signatur → 400, CORS, kein Docs-UI, Zeitlimit |
| Isolation | `test_free_isolation.py` | AST: kein `sectestx`, kein `subprocess`, kein Netz, kein `load_spec`, kein Schreibzugriff im Dienst |
| Keine Spuren | `test_keine_spuren.py` | leeres Verzeichnis nach Scan, Schreibversuch scheitert, Logs ohne Inhalt, keine Beispielwerte in der Antwort |
| Lint | Ruff (E, F, I, B, UP, SIM) | sauber |

Stand: 142 Tests in `oas-audit`, 11 in `wm-audit`, alle offline, keine Docker-Abhängigkeit.

## 13. Bewusste Entscheidungen

- **Web-App mit Server-Backend** statt reiner Browser-Ausführung (Entscheidung Christian). Folge: der
  Missbrauchsschutz ist in voller Länge nötig; die Datenschutz-Aussage wird über offenen Quellcode,
  Nachweis-Tests und Selbst-Hosting getragen.
- **Lead-Gate nur beim PDF-Prüfbericht.** Note, Befunde, Prüfsatz und Blindstellen sind ungegated.
- **Kein E-Mail-Gate vor dem Ergebnis, keine öffentlichen Reports, kein Nutzerkonto.**
- **Sensible Felder bei authentifizierten Operationen sind Prüfaufträge, keine belegten Critical-
  Befunde** — ein Banking-Endpunkt, der IBANs liefert, darf kein Falschalarm sein.
- **Belegte Aggregate behalten ihre Schwere.** Dreißig unauthentifizierte Operationen sind ein Befund,
  aber kein harmloser.
- **`multiprocessing` statt `subprocess`** im Sandbox-Pfad, damit der Isolationstest `subprocess`
  verbieten kann.
- **Keine `PolicyAction.active`-Regel in wm-audit** — das Feld ist ein Serialisierungsartefakt.

## 14. Bekannte Grenzen

- Regel- und Widget-Texte nur Deutsch; der Prüfsatz ist zweisprachig (Plan-Schritt 6 offen).
- Keine Zeilennummern zu den JSON-Pointern (Plan-Schritt 2 offen; Voraussetzung für SARIF).
- Prerenderte Seiten werfen React #418 (Hydration-Abweichung), bestand schon vorher; React rendert neu.
- Der Cookie-Banner überdeckt auf kurzen Viewports die Einwilligungs-Checkbox.
- `RLIMIT_AS` wird auf macOS nicht angenommen (Entwicklung); auf Linux (Betrieb) greift es.
- `wm-audit`-Fixtures sind konstruiert; ein echter, anonymisierter Export fehlt.
- Ein garantiertes False Negative der Demo: `PATCH /api/v1/users/me` deklariert
  `additionalProperties: false`, der Code ist verwundbar — die beste Illustration der Free/Pro-Grenze.

## 15. Roadmap

| Stufe | Inhalt |
|---|---|
| v1.1 | PDF-Prüfbericht mit Control-Mapping und E-Mail-Gate (Double-Opt-In, max. 2 Mails/Adresse/24 h, EU-Provider mit AVV); englische Regeltexte; Zeilennummern zu Pointern; SARIF 2.1.0 + JUnit; Security-Diff zweier Spec-Stände |
| später | Arazzo-1.1-Export des Prüfsatzes; CycloneDX-Service-BOM; Regel-Longtail-Seiten (`/checks/<slug>`) aus `GET /api/v1/checks`; webMethods-Profil zuschaltbar |

## 16. Glossar

| Begriff | Bedeutung |
|---|---|
| belegt | direkt aus dem Dokument ablesbar, mit Fundstelle; bewertet die Note |
| wahrscheinlich / Prüfauftrag | starkes Indiz, statisch nicht entscheidbar; nie bewertet |
| Stil-Beobachtung | Aggregat: trifft auf > 50 % der Operationen zu |
| Laufzeitlücke | Risikoklasse, die kein Dokument zeigen kann; gezählt, nie bewertet |
| Blindstelle | Struktur im Dokument, die die Analyse nicht ausgewertet hat |
| Notendeckel (cap) | Höchstnote einer Dimension, solange ein bestimmter Befund besteht |
| Prüfsatz | der abgeleitete Testfall-Katalog |
| JSON-Pointer | Fundstelle im Dokument (RFC 6901), `~1` steht für `/` |
