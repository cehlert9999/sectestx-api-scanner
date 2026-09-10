"""Öffentlicher Scan-Dienst — die einzige Netzwerkkante des freien Werkzeugs.

Grundsätze, die hier nicht verhandelbar sind:

* Die Spezifikation existiert nur im Arbeitsspeicher des Requests. Nichts wird
  auf Platte geschrieben, nichts geloggt, was aus dem Dokument stammt.
* Der Dienst sendet keinen Request an die beschriebene API. Es gibt keinen
  URL-Fetch — er wäre der einzige SSRF-Vektor.
* Jede Analyse läuft in einem eigenen Arbeitsprozess mit Ressourcenlimits und
  Wanduhr-Timeout. Eine Alias-Bombe kostet damit einen Prozess, nicht den Dienst.
* Der Dienst importiert nichts aus dem Pro-Produkt. Ein AST-Test sichert das ab.
"""

from oas_audit.service.app import create_app

__all__ = ["create_app"]
