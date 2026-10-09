# wm-audit

Statische Security-Analyse für **webMethods-API-Gateway-Exporte** — liest die tatsächliche
Konfiguration (Policies, native Endpunkte, Protokolle), nicht nur die Dokumentation.

Eine OpenAPI-Spezifikation sagt, was eine Schnittstelle tun *soll*. Ein Gateway-Export sagt,
was sie tatsächlich tut. Befunde aus dieser Quelle sind deshalb Feststellungen, keine
Vermutungen — ohne dass eine einzige Anfrage an die Schnittstelle nötig wäre.

**Läuft lokal.** Ein Export enthält `PassmanData` und Keystores. Er gehört auf keine Website;
Einträge unter `PassmanData`, `Keystore`, `Truststore` und `Kerberos` werden nie geöffnet,
nur gezählt (`GESPERRTE_ASSETS`).

```bash
pip install -e ../oas-audit -e .          # oas-audit + wm-audit
wm-audit export.zip                       # Bericht als Text
wm-audit export.zip --json                # Bericht als JSON (wm-audit-bericht/1)
wm-audit export/ --fail-on high           # Exit 1 bei belegtem Befund ≥ high
```

Regeln: keine Identify-and-Authorize-Policy, `allowAnonymous`, ODER-verknüpfte
Identifikation, nur Anwendungs-Identität, HTTP am Eingang, Klartext-Backend, durchgereichte
Security-Header, fehlende Traffic-Begrenzung, Log-Invocation. Keine Regel stützt sich auf
`PolicyAction.active` — das Feld ist in Exporten durchgehend `false` (Serialisierungsartefakt);
ein AST-Test sichert das ab.

Gelesen wird, was im Gateway tatsächlich greift:

- **Policy-Zuordnung:** Aktionen zählen nur, wenn die Policy sie in `policyEnforcements`
  einer Stage zuordnet. Eine verwaiste Aktion verdeckt keine Lücke.
- **Routing statt Spec:** Klartext-Backends werden am Ziel der Routing-Policy erkannt,
  `${Alias}` wird über einfache Aliase aufgelöst. `nativeEndpoint` (die Server der
  importierten Spec) dient nur ohne Routing-Policy als Ersatz.
- **Mehrere Umgebungen:** `test/` und `prod/` in einem Archiv bleiben getrennte APIs.
- **Robust und transparent:** eine Lesart für Werte (`"false"` bleibt falsch), Grenzen gegen
  ZIP- und JSON-Bomben, jede übersprungene Datei steht mit Grund im Bericht, Zugangsdaten
  in URLs werden geschwärzt.

Die Struktur echter Exporte stammt aus den öffentlichen Beispielen in
`SoftwareAG/webmethods-api-gateway-devops` (`WM_DEVOPS_REPO=… pytest -m echt`).

**Rust-Fassung:** [`../wm-audit-rs`](../wm-audit-rs) — ein Binary ohne Python-Laufzeit, für
Kunden mit Freigabeprozess. Beide Fassungen liefern byte-identische Berichte; die
Golden-Files unter `tests/golden` sind der Vertrag (`pytest -m rust` vergleicht beide).

Lizenz: Apache-2.0. Siehe `LICENSE` und `NOTICE`.
