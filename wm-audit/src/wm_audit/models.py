"""Datenmodell eines webMethods-API-Gateway-Exports.

Ein Export ist ein ZIP beziehungsweise Verzeichnis mit JSON-Assets. Anders als
eine OpenAPI-Spezifikation beschreibt er nicht, was eine Schnittstelle tun
*sollte*, sondern wie das Gateway sie tatsächlich ausliefert: welche Policies
greifen, welches Backend angesprochen wird, welche Protokolle erlaubt sind.

Das macht Befunde aus dieser Quelle belastbarer als solche aus einer Spec — sie
sind Aussagen über die Konfiguration, nicht über die Dokumentation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(BaseModel):
    """Eine einzelne Policy-Aktion, z.B. „Identify & Authorize"."""

    id: str = ""
    name: str = ""
    template_key: str = ""  # z.B. "evaluatePolicy", "entryProtocolPolicy"
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    #: Achtung: im Export steht dieses Feld durchgehend auf ``False`` — es ist
    #: ein Serialisierungsartefakt und **kein** Hinweis darauf, ob die Policy im
    #: Gateway greift. Es wird deshalb bewusst von keiner Regel ausgewertet.
    active_flag: bool = False

    def value(self, template_key: str) -> str | None:
        """Erster Wert eines direkten Parameters."""
        vals = self.values(template_key)
        return vals[0] if vals else None

    def values(self, template_key: str) -> list[str]:
        """Alle Werte eines direkten Parameters."""
        for p in self.parameters:
            if p.get("templateKey") == template_key:
                return [str(v) for v in (p.get("values") or [])]
        return []

    def groups(self, template_key: str) -> list[dict[str, Any]]:
        """Verschachtelte Parameter-Gruppen, z.B. jede ``IdentificationRule``."""
        return [p for p in self.parameters if p.get("templateKey") == template_key]

    @staticmethod
    def group_values(group: dict[str, Any], template_key: str) -> list[str]:
        for p in group.get("parameters", []) or []:
            if p.get("templateKey") == template_key:
                return [str(v) for v in (p.get("values") or [])]
        return []


class NativeEndpoint(BaseModel):
    """Das Backend, an das das Gateway weiterleitet."""

    uri: str = ""
    pass_security_headers: bool = False
    connection_timeout: int = 0

    @property
    def is_plaintext(self) -> bool:
        return self.uri.lower().startswith("http://")


class GatewayApi(BaseModel):
    """Eine im Gateway konfigurierte API samt Policies und eingebetteter Spec."""

    id: str = ""
    name: str = ""
    version: str | None = None
    type: str = ""  # "rest", "soap", "graphql"
    is_active: bool = True
    maturity_state: str = ""
    api_groups: list[str] = Field(default_factory=list)

    native_endpoints: list[NativeEndpoint] = Field(default_factory=list)
    policy_actions: list[PolicyAction] = Field(default_factory=list)

    #: Die vom Gateway gehaltene OpenAPI-/Swagger-Definition. Sie erzeugt beim
    #: Import die Ressourcen und Operationen — was hier steht, liefert das
    #: Gateway auch aus. ``oas_audit`` kann sie unverändert weiterverarbeiten.
    api_definition: dict[str, Any] | None = None

    #: Herkunft im Export, für die Evidence-Angabe im Befund.
    source_path: str = ""

    def actions(self, template_key: str) -> list[PolicyAction]:
        return [a for a in self.policy_actions if a.template_key == template_key]

    def has_action(self, template_key: str) -> bool:
        return any(a.template_key == template_key for a in self.policy_actions)

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name


class GatewayExport(BaseModel):
    """Ein eingelesener Export."""

    apis: list[GatewayApi] = Field(default_factory=list)
    source: str = ""

    def __len__(self) -> int:
        return len(self.apis)
