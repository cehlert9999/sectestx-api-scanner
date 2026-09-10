"""OpenAPI-Parser (Swagger 2.0 + OpenAPI 3.x) → internes Endpoint-Modell."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonref
import yaml

from oas_audit.models import (
    Endpoint,
    HttpMethod,
    PathParameter,
    SecurityRequirement,
)


class OpenAPIParser:
    """Konvertiert eine OpenAPI-3.x-Spec in eine Liste von Endpoints."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec
        self.is_v2 = "swagger" in spec and str(spec["swagger"]).startswith("2")
        self.is_v3 = "openapi" in spec and str(spec["openapi"]).startswith("3")

        if not (self.is_v2 or self.is_v3):
            raise ValueError("Nur Swagger 2.0 und OpenAPI 3.x werden unterstützt.")

        if self.is_v2:
            self._security_schemes = spec.get("securityDefinitions", {}) or {}
        else:
            self._security_schemes = spec.get("components", {}).get("securitySchemes", {}) or {}

    # ------------------------------------------------------------------
    # öffentliche API
    # ------------------------------------------------------------------

    def parse(self) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        paths = self.spec.get("paths", {}) or {}
        global_security = self.spec.get("security", []) or []

        for path, ops in paths.items():
            if not isinstance(ops, dict):
                continue
            common_params = ops.get("parameters", []) or []
            for verb, operation in ops.items():
                if verb.upper() not in HttpMethod.__members__:
                    continue
                if not isinstance(operation, dict):
                    continue
                endpoints.append(
                    self._build_endpoint(
                        path=path,
                        verb=verb,
                        operation=operation,
                        path_level_params=common_params,
                        global_security=global_security,
                    )
                )
        return endpoints

    # ------------------------------------------------------------------
    # interne Helpers
    # ------------------------------------------------------------------

    def _build_endpoint(
        self,
        *,
        path: str,
        verb: str,
        operation: dict[str, Any],
        path_level_params: list[dict[str, Any]],
        global_security: list[Any],
    ) -> Endpoint:
        all_params_raw = path_level_params + (operation.get("parameters", []) or [])
        path_params: list[PathParameter] = []
        query_params: list[PathParameter] = []
        for raw in all_params_raw:
            param = raw
            in_type = param.get("in")
            if in_type not in ("path", "query"):
                continue

            if self.is_v2:
                schema_type = param.get("format") or param.get("type")
            else:
                schema = param.get("schema", {}) or {}
                schema_type = schema.get("format") or schema.get("type")

            parsed_param = PathParameter(
                name=param["name"],
                schema_type=schema_type,
                description=param.get("description"),
            )

            if in_type == "path":
                path_params.append(parsed_param)
            elif in_type == "query":
                query_params.append(parsed_param)

        request_schema = self._extract_request_schema(operation)
        response_schemas = self._extract_response_schemas(operation)
        security_alternatives = self._resolve_security_alternatives(operation, global_security)
        security = [req for group in security_alternatives for req in group]
        if "security" in operation:
            security_source = "operation"
        elif global_security:
            security_source = "global"
        else:
            security_source = "none"

        return Endpoint(
            method=HttpMethod(verb.upper()),
            path=path,
            operation_id=operation.get("operationId"),
            summary=operation.get("summary"),
            tags=operation.get("tags", []) or [],
            path_parameters=path_params,
            query_parameters=query_params,
            request_schema=request_schema,
            response_schemas=response_schemas,
            deprecated=bool(operation.get("deprecated", False)),
            security=security,
            security_alternatives=security_alternatives,
            security_source=security_source,
            pointer=operation_pointer(path, verb),
            response_codes=[str(c) for c in (operation.get("responses", {}) or {})],
            request_content_types=self._request_content_types(operation),
        )

    def _request_content_types(self, operation: dict[str, Any]) -> list[str]:
        if self.is_v2:
            params = operation.get("parameters", []) or []
            if not any(p.get("in") in ("body", "formData") for p in params):
                return []
            declared = operation.get("consumes") or self.spec.get("consumes") or []
            if any(p.get("in") == "formData" and p.get("type") == "file" for p in params):
                declared = list(declared) + ["multipart/form-data"]
            return sorted(set(declared))
        body = operation.get("requestBody") or {}
        return sorted((body.get("content") or {}).keys())

    def _extract_request_schema(self, operation: dict[str, Any]) -> dict[str, Any] | None:
        if self.is_v2:
            # Swagger 2.0: requestBody is in parameters with in="body"
            params = operation.get("parameters", []) or []
            for param in params:
                if param.get("in") == "body":
                    return param.get("schema")
            form = [p for p in params if p.get("in") == "formData"]
            if form:
                props: dict[str, Any] = {}
                for p in form:
                    if p.get("type") == "file":
                        props[p["name"]] = {"type": "string", "format": "binary"}
                    else:
                        props[p["name"]] = {k: v for k, v in p.items()
                                            if k in ("type", "format", "maxLength", "enum")}
                return {"type": "object", "properties": props}
            return None

        body = operation.get("requestBody")
        if not body:
            return None
        content = body.get("content", {}) or {}
        for media_type in ("application/json", "application/*+json"):
            if media_type in content:
                schema = content[media_type].get("schema")
                if schema:
                    return schema
        for media in content.values():
            if "schema" in media:
                return media["schema"]
        return None

    def _extract_response_schemas(
        self, operation: dict[str, Any]
    ) -> dict[int, dict[str, Any]]:
        out: dict[int, dict[str, Any]] = {}
        for status_str, resp in (operation.get("responses", {}) or {}).items():
            try:
                code = int(status_str)
            except (TypeError, ValueError):
                continue

            if self.is_v2:
                schema = resp.get("schema")
                if schema is not None:
                    out[code] = schema
                continue

            content = resp.get("content", {}) or {}
            schema = None
            if "application/json" in content:
                schema = content["application/json"].get("schema")
            else:
                for media in content.values():
                    if "schema" in media:
                        schema = media["schema"]
                        break
            if schema is not None:
                out[code] = schema
        return out

    def _resolve_security(
        self, operation: dict[str, Any], global_security: list[Any]
    ) -> list[SecurityRequirement]:
        """Flache Liste aller Requirements — beantwortet nur „braucht Auth?"."""
        return [req for group in self._resolve_security_alternatives(operation, global_security)
                for req in group]

    def _resolve_security_alternatives(
        self, operation: dict[str, Any], global_security: list[Any]
    ) -> list[list[SecurityRequirement]]:
        """Erhält die Struktur der Spec: äußere Liste ODER, innere UND.

        ``security: [{A: []}, {B: []}]``   → [[A], [B]]  — A *oder* B genügt
        ``security: [{A: [], B: []}]``     → [[A, B]]    — A *und* B nötig

        Der Unterschied ist sicherheitsrelevant und geht in der flachen Liste
        verloren: hinter einem API-Gateway ist „API-Key ODER Token" fast immer
        ein Fehler, wo „API-Key UND Token" gemeint war.
        """
        sec_list = operation.get("security", global_security) or []
        out: list[list[SecurityRequirement]] = []
        for sec in sec_list:
            if not isinstance(sec, dict):
                continue
            group: list[SecurityRequirement] = []
            for scheme_name in sec:
                scheme = self._security_schemes.get(scheme_name)
                if not scheme:
                    continue
                group.append(
                    SecurityRequirement(
                        type=scheme.get("type", "unknown"),
                        scheme=scheme.get("scheme"),
                        name=scheme.get("name"),
                        location=scheme.get("in"),
                    )
                )
            if group:
                out.append(group)
        return out

def json_pointer(*segments: str) -> str:
    """Baut einen JSON-Pointer (RFC 6901) mit korrekter Maskierung."""
    return "#/" + "/".join(s.replace("~", "~0").replace("/", "~1") for s in segments)


def operation_pointer(path: str, verb: str) -> str:
    return json_pointer("paths", path, verb.lower())


def extract_base_url(spec: dict[str, Any]) -> str | None:
    """Extrahiert die effektive Base-URL aus einer Swagger-2.0- oder OpenAPI-3.x-Spec.

    webMethods API Gateway schreibt die Gateway-Endpoint-URL direkt in die Spec:
    - Swagger 2.0: schemes[0] + host + basePath  (z.B. https://gw:5555/gateway/API/1.0)
    - OpenAPI 3.x: servers[0].url (Server-Variablen werden mit ihrem Default aufgelöst)
    """
    is_v2 = "swagger" in spec and str(spec.get("swagger", "")).startswith("2")

    if is_v2:
        host = spec.get("host")
        if not host:
            return None
        schemes = spec.get("schemes") or ["https"]
        scheme = schemes[0]
        base_path = spec.get("basePath", "") or ""
        if base_path == "/":
            base_path = ""
        return f"{scheme}://{host}{base_path}"

    # OpenAPI 3.x
    servers = spec.get("servers") or []
    if not servers:
        return None
    url: str = servers[0].get("url", "") or ""
    variables = servers[0].get("variables") or {}
    for var_name, var_def in variables.items():
        default = var_def.get("default", "") if isinstance(var_def, dict) else ""
        url = url.replace(f"{{{var_name}}}", default)
    # Relative URLs (z.B. "/api/v3") sind für den User wertlos — lieber None
    if url and not url.startswith(("http://", "https://")):
        return None
    return url or None


def load_spec(source: str) -> dict[str, Any]:
    """Lädt eine OpenAPI-Spec entweder von URL oder Datei (JSON oder YAML)."""
    source = source.strip()

    # Tolerant parsing for URL protocol typos (e.g. single-slash or missing slash)
    if "://" not in source:
        if source.startswith("https:/"):
            source = "https://" + source[7:]
        elif source.startswith("http:/"):
            source = "http://" + source[6:]
        elif source.startswith("https/"):
            source = "https://" + source[6:]
        elif source.startswith("http/"):
            source = "http://" + source[5:]

    if source.startswith(("http://", "https://")):
        try:
            import httpx  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Spec-Laden per URL benoetigt httpx: pip install 'oas-audit[fetch]'"
            ) from exc
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.get(source)
            resp.raise_for_status()
            return _parse_text(resp.text, hint=resp.headers.get("content-type", ""))

    path = Path(source).expanduser().resolve()
    text = path.read_text(encoding="utf-8")
    return _parse_text(text, hint=path.suffix.lower())


def _parse_text(text: str, *, hint: str = "") -> dict[str, Any]:
    hint = hint.lower()
    text = text.strip()

    def _load():
        if hint.endswith((".yaml", ".yml")) or "yaml" in hint:
            return yaml.safe_load(text)
        if hint.endswith(".json") or "json" in hint:
            return json.loads(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return yaml.safe_load(text)

    raw_dict = _load()
    # jsonref.replace_refs resolves all $ref automatically!
    return jsonref.replace_refs(raw_dict, lazy_load=False)
