"""Endpoint-Klassifikator — rein regelbasiert, kein LLM.

Bestimmt für jeden Endpoint Eigenschaften wie ID-Like-Parameter,
Operation-Type (Read/Create/Update/...) und einen Resource-Hint.
"""

from __future__ import annotations

import re

from oas_audit.models import (
    ClassifiedEndpoint,
    Endpoint,
    HttpMethod,
    OperationType,
    PathParameter,
)

_ID_NAME_RE = re.compile(
    r"(?:^|_)id$|^id$|_uuid$|^uuid$|number$|code$",
    re.IGNORECASE,
)
_ID_TYPE_HINTS = {"uuid", "integer", "int32", "int64"}

# Pagination-/Sortier-/Steuerungs-Parameter sind oft Integer, aber KEINE
# Objekt-Identifier. Ohne diese Deny-Liste würde z.B. ?offset=/?limit= als
# id-like gelten und BOLA-Patterns wie param_duplication auf Pagination-Params
# matchen — was eine nie befüllte Bruno-Variable (z.B. {{offsets_id_a}})
# erzeugt. Exakter (case-insensitiver) Namensabgleich.
_NON_ID_QUERY_NAMES = {
    "offset", "limit", "page", "size", "per_page", "perpage",
    "page_size", "pagesize", "page_number", "pagenumber", "skip",
    "count", "top", "length", "start", "max_results", "maxresults",
    "sort", "order", "order_by", "sort_by", "q", "query", "search",
    "fields", "expand", "include", "filter",
}


def is_id_like(param: PathParameter) -> bool:
    """Heuristik: Sieht der Parameter wie ein Resource-Identifier aus?"""
    if param.name.lower() in _NON_ID_QUERY_NAMES:
        return False
    if _ID_NAME_RE.search(param.name):
        return True
    return bool(param.schema_type and param.schema_type.lower() in _ID_TYPE_HINTS)


def find_id_like_param(endpoint: Endpoint) -> PathParameter | None:
    """Gibt den letzten ID-Like-Path-Parameter zurück (typisch der für die
    aktuelle Resource — bei /users/{userId}/orders/{orderId} ist orderId
    relevanter für BOLA-Tests gegen /orders)."""
    for param in reversed(endpoint.path_parameters):
        if is_id_like(param):
            return param
    return None


def find_id_like_query_params(endpoint: Endpoint) -> list[PathParameter]:
    """Sucht nach Query-Parametern, die wie IDs aussehen (für Duplication-Tests)."""
    return [p for p in endpoint.query_parameters if is_id_like(p)]


def derive_resource_hint(endpoint: Endpoint) -> str | None:
    """Versucht aus dem Pfad einen Ressourcen-Namen zu extrahieren.

    /api/v1/partners/{partner_id}              → "partners"
    /api/v1/partners/by-number/{partner_number} → "partners"  (by-X überspringen)
    /api/v1/contracts/{contract_id}/status      → "contracts" (Action-Suffix überspringen)
    """
    segments = [s for s in endpoint.path.split("/") if s]

    # Letzten Path-Parameter-Index bestimmen
    last_param_idx: int | None = None
    for i, s in enumerate(segments):
        if s.startswith("{"):
            last_param_idx = i

    if last_param_idx is None:
        # Kein Parameter → letztes sinnvolles Segment
        candidates = [
            s for s in segments
            if not s.startswith("{") and s != "api" and not re.match(r"^v\d+$", s)
        ]
        return candidates[-1] if candidates else None

    # Rückwärts vom letzten Parameter suchen; Aktions-Prefixe überspringen
    for i in range(last_param_idx - 1, -1, -1):
        seg = segments[i]
        if seg.startswith("{"):
            continue
        if "-" in seg or re.match(r"^v\d+$", seg) or seg == "api":
            continue
        return seg

    return None


def derive_operation_type(endpoint: Endpoint) -> OperationType:
    method = endpoint.method
    if method == HttpMethod.POST:
        return OperationType.CREATE
    if method == HttpMethod.PUT:
        return OperationType.UPDATE
    if method == HttpMethod.PATCH:
        return OperationType.UPDATE
    if method == HttpMethod.DELETE:
        return OperationType.DELETE
    if method == HttpMethod.GET:
        # Ein Path-Param am Ende deutet auf Read; sonst List.
        if endpoint.path_parameters and endpoint.path.rstrip("/").endswith("}"):
            return OperationType.READ
        return OperationType.LIST
    return OperationType.ACTION


def classify(endpoint: Endpoint, login_endpoint: str | None = None) -> ClassifiedEndpoint:
    is_login = False
    if login_endpoint and endpoint.path == login_endpoint and endpoint.method == HttpMethod.POST:
        is_login = True

    return ClassifiedEndpoint(
        endpoint=endpoint,
        operation_type=derive_operation_type(endpoint),
        id_like_parameter=find_id_like_param(endpoint),
        id_like_query_parameters=find_id_like_query_params(endpoint),
        resource_hint=derive_resource_hint(endpoint),
        is_login_endpoint=is_login,
    )


def classify_all(endpoints: list[Endpoint], login_endpoint: str | None = None) -> list[ClassifiedEndpoint]:
    classified = [classify(e, login_endpoint) for e in endpoints]

    # Second Pass: GET-Endpunkte für PUT/PATCH auffinden (US-10)
    get_endpoints = {
        ep.endpoint.path: ep.endpoint
        for ep in classified
        if ep.endpoint.method == HttpMethod.GET
    }

    for ep in classified:
        if ep.endpoint.method in (HttpMethod.PUT, HttpMethod.PATCH):
            ep.paired_read_endpoint = get_endpoints.get(ep.endpoint.path)

    # Third Pass: für GET /resource/{id} den passenden LIST-Endpoint GET /resource
    # finden. Ermöglicht US-03 (echte Ressourcen-IDs in BOLA-Tests).
    get_list_by_path = {
        ep.endpoint.path: ep.endpoint
        for ep in classified
        if ep.endpoint.method == HttpMethod.GET
        and ep.operation_type == OperationType.LIST
    }

    for ep in classified:
        if ep.id_like_parameter is None or not ep.endpoint.path.rstrip("/").endswith("}"):
            continue
        # Vorgänger-Pfad ohne den letzten /{param}-Teil
        list_path = ep.endpoint.path.rsplit("/", 1)[0] or "/"
        list_ep = get_list_by_path.get(list_path)
        if list_ep is not None:
            ep.paired_list_endpoint = list_ep

    # Fourth Pass: pro Pfad alle dokumentierten HTTP-Methoden sammeln.
    # Speist recon.undocumented_method (Shadow Endpoints, Phase 2).
    methods_by_path: dict[str, list[HttpMethod]] = {}
    for ep in classified:
        methods_by_path.setdefault(ep.endpoint.path, []).append(ep.endpoint.method)
    for ep in classified:
        ep.documented_methods = sorted(
            set(methods_by_path[ep.endpoint.path]), key=lambda m: m.value
        )

    return classified
