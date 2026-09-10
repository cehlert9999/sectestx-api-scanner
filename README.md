# sectestx API Scanner — der freie Teil von sectestx

Statische OWASP-Security-Analyse für API-Spezifikationen und webMethods-API-Gateway-Exporte —
**ohne einen einzigen Request an die beschriebene API**. Das ist der offene Kern hinter
[sectestx.leanofy.de/check](https://sectestx.leanofy.de/check).

| Paket | Liest | Sagt aus über |
|---|---|---|
| [`oas-audit`](./oas-audit.md) (dieses Verzeichnis) | OpenAPI 3.x / Swagger 2.0 | die Spezifikation |
| [`wm-audit`](./wm-audit/) | webMethods-API-Gateway-Export (ZIP) | die tatsächliche Gateway-Konfiguration |

Die Grenze in einem Satz: **statisch = offen, verifiziert/ausführbar = Pro.**
Was hier liegt, leitet aus Dokumenten Befunde und einen Prüfsatz ab. Was Requests baut,
ausführt und Evidence liefert, ist [sectestx](https://sectestx.leanofy.de).

- Was mit einer hochgeladenen Spezifikation passiert, und welcher Test das belegt: [`TRANSPARENZ.md`](./TRANSPARENZ.md)
- Betrieb des Scan-Dienstes, auch intern: [`deploy/README.md`](./deploy/README.md)

```bash
pip install -e ".[service]"     # oas-audit mit Dienst
oas-audit openapi.yaml           # Bericht
oas-audit openapi.yaml --catalog # Prüfsatz als Markdown
pytest -q                        # 140+ Tests, alle offline
```

Lizenz: Apache-2.0.
