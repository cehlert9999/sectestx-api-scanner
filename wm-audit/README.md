# wm-audit

Statische Security-Analyse für **webMethods-API-Gateway-Exporte** — liest die tatsächliche
Konfiguration (Policies, native Endpunkte, Protokolle), nicht nur die Dokumentation.

Eine OpenAPI-Spezifikation sagt, was eine Schnittstelle tun *soll*. Ein Gateway-Export sagt,
was sie tatsächlich tut. Befunde aus dieser Quelle sind deshalb Feststellungen, keine
Vermutungen — ohne dass eine einzige Anfrage an die Schnittstelle nötig wäre.

**Läuft lokal.** Ein Export enthält `PassmanData` und Keystores. Er gehört auf keine Website;
der Reader liest diese Assets bewusst gar nicht erst ein (`GESPERRTE_ASSETS`).

```bash
pip install -e ../  -e .          # oas-audit + wm-audit
python -c "
from wm_audit import read_export, run_rules
for f in run_rules(read_export('export.zip')):
    print(f.severity.value, f.confidence.value, f.check_id, f.subject)
"
```

Regeln u. a.: keine Identify-and-Authorize-Policy, `allowAnonymous`, ODER-verknüpfte
Identifikation, nur Anwendungs-Identität, HTTP am Eingang, Klartext-Backend, durchgereichte
Security-Header, fehlende Traffic-Begrenzung, Log-Invocation. Keine Regel stützt sich auf
`PolicyAction.active` — das Feld ist in Exporten durchgehend `false` (Serialisierungsartefakt);
ein AST-Test sichert das ab.

Lizenz: Apache-2.0. Siehe `LICENSE` und `NOTICE`.
