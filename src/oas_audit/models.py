"""Internes Datenmodell — vom OpenAPI-Dokument entkoppelt.

Klassifikator und Regeln arbeiten ausschließlich auf diesen Modellen, nicht auf
dem rohen OpenAPI-JSON. Damit kann ein anderer Parser (SoapUI, WSDL, Postman)
dasselbe Modell befüllen, ohne dass eine Regel angefasst werden muss.

Dieses Modul enthält bewusst nur die *statische* Hälfte: was in einer
Spezifikation steht. Alles, was einen ausgeführten Request beschreibt
(TestCase, TestStep, Assertion), gehört nicht hierher.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class OperationType(str, enum.Enum):
    LIST = "list"
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ACTION = "action"


class OWASPCategory(str, enum.Enum):
    API1 = "API1"  # Broken Object Level Authorization
    API2 = "API2"  # Broken Authentication
    API3 = "API3"  # Broken Object Property Level Authorization
    API4 = "API4"  # Unrestricted Resource Consumption
    API5 = "API5"  # Broken Function Level Authorization
    API8 = "API8"  # Security Misconfiguration
    API9 = "API9"  # Improper Inventory Management


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PathParameter(BaseModel):
    name: str
    schema_type: str | None = None  # z.B. "string", "integer", "uuid"
    description: str | None = None


class SecurityRequirement(BaseModel):
    """Was an Auth nötig ist — Bearer, Basic, ApiKey ..."""

    type: str  # "http", "apiKey", "oauth2", ...
    scheme: str | None = None  # "bearer", "basic"
    name: str | None = None  # für apiKey: Header-/Query-Parameter-Name
    location: str | None = None  # für apiKey: "header", "query", "cookie"


class Endpoint(BaseModel):
    """Normalisierte Endpoint-Repräsentation, vom Parser befüllt."""

    method: HttpMethod
    path: str
    operation_id: str | None = None
    summary: str | None = None
    tags: list[str] = Field(default_factory=list)
    path_parameters: list[PathParameter] = Field(default_factory=list)
    query_parameters: list[PathParameter] = Field(default_factory=list)
    request_schema: dict[str, Any] | None = None
    response_schemas: dict[int, dict[str, Any]] = Field(default_factory=dict)
    deprecated: bool = False

    # Flache Liste aller Security-Requirements. Verliert die ODER-Semantik der
    # Spezifikation und ist deshalb nur für „braucht der Endpoint überhaupt
    # Auth?" verwendbar — nicht für die Frage, welche Kombination gilt.
    security: list[SecurityRequirement] = Field(default_factory=list)

    # Die Security-Struktur, wie sie in der Spec steht: die äußere Liste ist ein
    # ODER, die innere ein UND. `security: [{A: []}, {B: []}]` heißt also
    # „A ODER B genügt" — ein häufiges Missverständnis und die Ursache realer
    # Auth-Bypässe hinter API-Gateways, wo API-Key UND Token gemeint waren.
    # Ohne dieses Feld ist dieser Fehler nicht erkennbar.
    security_alternatives: list[list[SecurityRequirement]] = Field(default_factory=list)

    # Woher das Security-Requirement stammt: "operation" (an der Operation selbst
    # gesetzt, auch wenn leer), "global" (vom Dokument geerbt) oder "none".
    security_source: str = "none"

    # JSON-Pointer auf die Operation im Quelldokument, z.B. "#/paths/~1orders/post".
    # Jeder Befund verweist darauf — ohne Fundstelle ist ein Befund eine Behauptung.
    pointer: str = ""

    # Alle dokumentierten Antwort-Codes als Text ("200", "4XX", "default"), auch
    # solche ohne Schema. `response_schemas` enthält nur numerische Codes mit Schema.
    response_codes: list[str] = Field(default_factory=list)

    # Media-Types des Request-Bodys ("application/json", "multipart/form-data", ...).
    request_content_types: list[str] = Field(default_factory=list)

    @property
    def has_path_parameter(self) -> bool:
        return len(self.path_parameters) > 0

    @property
    def requires_auth(self) -> bool:
        return len(self.security) > 0

    @property
    def has_alternative_auth(self) -> bool:
        """True, wenn mehrere Auth-Wege alternativ (ODER) akzeptiert werden.

        Dann entscheidet das schwächste Glied über die tatsächliche Sicherheit
        des Endpoints.
        """
        return len(self.security_alternatives) > 1


class ClassifiedEndpoint(BaseModel):
    """Endpoint plus die vom Klassifikator abgeleiteten Eigenschaften."""

    endpoint: Endpoint
    operation_type: OperationType
    id_like_parameter: PathParameter | None = None
    id_like_query_parameters: list[PathParameter] = Field(default_factory=list)
    resource_hint: str | None = None  # aus dem Pfad abgeleiteter Ressourcen-Name
    paired_read_endpoint: Endpoint | None = None  # GET zum selben Pfad (für PUT/PATCH)
    # Für GET /resource/{id} der zugehörige LIST-Endpunkt GET /resource.
    paired_list_endpoint: Endpoint | None = None
    is_login_endpoint: bool = False
    # Alle HTTP-Methoden, die für *denselben Pfad* dokumentiert sind.
    documented_methods: list[HttpMethod] = Field(default_factory=list)

    @property
    def is_id_keyed_read(self) -> bool:
        return (
            self.endpoint.method == HttpMethod.GET
            and self.id_like_parameter is not None
            and self.operation_type == OperationType.READ
        )
