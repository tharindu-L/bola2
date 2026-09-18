"""OpenAPI 3.x discovery backend.

Parses a local or remote OpenAPI document into the unified Operation model.
Generic: no target-specific assumptions about path names, parameter names, or
schema shapes. Every heuristic here operates on structural signals present in
any OpenAPI document (parameter `in`, schema types, required fields).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests
import yaml

from bola_framework.discovery.base import Discoverer
from bola_framework.models import (
    ApiType,
    DiscoverySource,
    HttpMethod,
    Operation,
    OperationType,
    Parameter,
    ParameterLocation,
    REST_METHOD_TO_OPERATION_TYPE,
)

logger = logging.getLogger(__name__)

_PARAM_LOCATION_MAP = {
    "path": ParameterLocation.PATH,
    "query": ParameterLocation.QUERY,
    "header": ParameterLocation.HEADER,
    "cookie": ParameterLocation.COOKIE,
}

_METHODS = {m.value.lower(): m for m in HttpMethod}


class OpenApiDiscoverer(Discoverer):
    """Extracts paths, methods, parameters, request bodies, and response
    schemas from an OpenAPI 3.x document."""

    def __init__(self, source: str, base_url: Optional[str] = None, timeout: float = 15.0):
        """`source` may be a local file path or an http(s) URL to the spec."""
        self.source = source
        self._explicit_base_url = base_url
        self.timeout = timeout
        self._spec: dict = {}

    def _load_spec(self) -> dict:
        if self.source.startswith("http://") or self.source.startswith("https://"):
            resp = requests.get(self.source, timeout=self.timeout)
            resp.raise_for_status()
            text = resp.text
        else:
            text = Path(self.source).read_text(encoding="utf-8")

        text_stripped = text.lstrip()
        if text_stripped.startswith("{"):
            return json.loads(text)
        return yaml.safe_load(text)

    def _resolve_base_url(self, spec: dict) -> str:
        if self._explicit_base_url:
            return self._explicit_base_url
        servers = spec.get("servers") or []
        if servers and isinstance(servers, list):
            url = servers[0].get("url", "")
            if url:
                return url
        return ""

    def discover(self) -> list[Operation]:
        spec = self._load_spec()
        self._spec = spec
        base_url = self._resolve_base_url(spec)
        components_schemas = spec.get("components", {}).get("schemas", {})

        operations: list[Operation] = []
        paths = spec.get("paths", {}) or {}

        for path_template, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            shared_params = path_item.get("parameters", [])

            for method_str, op_obj in path_item.items():
                if method_str.lower() not in _METHODS:
                    continue
                if not isinstance(op_obj, dict):
                    continue

                method = _METHODS[method_str.lower()]
                op_id = op_obj.get(
                    "operationId", f"{method.value}_{path_template}"
                )

                parameters = self._extract_parameters(
                    shared_params + op_obj.get("parameters", [])
                )

                body_schema = self._extract_request_body(op_obj, components_schemas)
                body_params = self._flatten_body_parameters(body_schema)
                parameters.extend(body_params)

                response_schema = self._extract_response_schema(
                    op_obj, components_schemas
                )

                security = op_obj.get("security", spec.get("security"))
                requires_auth = bool(security) if security is not None else True

                operation = Operation(
                    operation_id=str(op_id),
                    api_type=ApiType.REST,
                    operation_type=REST_METHOD_TO_OPERATION_TYPE.get(
                        method, OperationType.UNKNOWN
                    ),
                    source=DiscoverySource.OPENAPI,
                    http_method=method,
                    path_template=path_template,
                    base_url=base_url,
                    parameters=parameters,
                    request_body_schema=body_schema,
                    response_schema=response_schema,
                    requires_auth=requires_auth,
                    tags=op_obj.get("tags", []),
                    raw_metadata={"summary": op_obj.get("summary", "")},
                )
                operations.append(operation)

        logger.info("OpenAPI discovery produced %d operations", len(operations))
        return operations

    @staticmethod
    def _extract_parameters(raw_params: list[dict]) -> list[Parameter]:
        params: list[Parameter] = []
        for raw in raw_params:
            if not isinstance(raw, dict) or "in" not in raw:
                continue
            location = _PARAM_LOCATION_MAP.get(raw["in"])
            if location is None:
                continue
            schema = raw.get("schema", {})
            params.append(
                Parameter(
                    name=raw.get("name", ""),
                    location=location,
                    type_hint=schema.get("type"),
                    required=bool(raw.get("required", False)),
                    example=raw.get("example", schema.get("example")),
                )
            )
        return params

    def _extract_request_body(
        self, op_obj: dict, components_schemas: dict
    ) -> dict:
        body = op_obj.get("requestBody", {})
        content = body.get("content", {})
        for media_type in ("application/json", "application/x-www-form-urlencoded"):
            if media_type in content:
                schema = content[media_type].get("schema", {})
                return self._resolve_schema(schema, components_schemas)
        return {}

    def _extract_response_schema(self, op_obj: dict, components_schemas: dict) -> dict:
        responses = op_obj.get("responses", {})
        for status in ("200", "201", "default"):
            resp = responses.get(status)
            if not resp:
                continue
            content = resp.get("content", {})
            json_content = content.get("application/json", {})
            schema = json_content.get("schema", {})
            if schema:
                return self._resolve_schema(schema, components_schemas)
        return {}

    def _resolve_schema(self, schema: dict, components_schemas: dict, depth: int = 0) -> dict:
        if depth > 8 or not isinstance(schema, dict):
            return schema if isinstance(schema, dict) else {}
        ref = schema.get("$ref")
        if ref and ref.startswith("#/components/schemas/"):
            name = ref.rsplit("/", 1)[-1]
            resolved = components_schemas.get(name, {})
            return self._resolve_schema(resolved, components_schemas, depth + 1)
        if schema.get("type") == "array" and "items" in schema:
            return {
                "type": "array",
                "items": self._resolve_schema(schema["items"], components_schemas, depth + 1),
            }
        if "properties" in schema:
            resolved_props = {
                k: self._resolve_schema(v, components_schemas, depth + 1)
                for k, v in schema["properties"].items()
            }
            return {**schema, "properties": resolved_props}
        return schema

    @staticmethod
    def _flatten_body_parameters(body_schema: dict, prefix: str = "") -> list[Parameter]:
        """Turn a resolved JSON schema into a flat list of body Parameters with
        dotted json_path locations, so nested identifiers (e.g. data.object.id)
        are visible to the identifier detector."""
        params: list[Parameter] = []
        if not isinstance(body_schema, dict):
            return params

        if body_schema.get("type") == "array":
            item_schema = body_schema.get("items", {})
            params.extend(
                OpenApiDiscoverer._flatten_body_parameters(item_schema, prefix)
            )
            return params

        properties = body_schema.get("properties", {})
        required = set(body_schema.get("required", []))
        for name, prop_schema in properties.items():
            json_path = f"{prefix}.{name}" if prefix else name
            prop_type = prop_schema.get("type") if isinstance(prop_schema, dict) else None
            params.append(
                Parameter(
                    name=name,
                    location=ParameterLocation.BODY,
                    type_hint=prop_type,
                    required=name in required,
                    example=prop_schema.get("example") if isinstance(prop_schema, dict) else None,
                    json_path=json_path,
                )
            )
            if isinstance(prop_schema, dict) and (
                prop_schema.get("type") == "object" or "properties" in prop_schema
            ):
                params.extend(
                    OpenApiDiscoverer._flatten_body_parameters(prop_schema, json_path)
                )
            elif isinstance(prop_schema, dict) and prop_schema.get("type") == "array":
                items = prop_schema.get("items", {})
                if isinstance(items, dict) and "properties" in items:
                    params.extend(
                        OpenApiDiscoverer._flatten_body_parameters(items, json_path)
                    )
        return params
