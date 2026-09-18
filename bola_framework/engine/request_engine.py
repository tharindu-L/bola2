"""Request Engine.

Converts a (Operation, Principal, identifier bindings) triple into an actual
HTTP request -- REST via `requests`, GraphQL via a hand-serialized
query/variables pair sent as JSON POST -- and returns a redacted
RequestRecord capturing everything the BOLA Analyzer and report generator
need, without ever persisting raw secrets.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from bola_framework.auth.session_manager import Principal
from bola_framework.engine.graphql_builder import build_query
from bola_framework.models import ApiType, Operation, ParameterLocation
from bola_framework.models.finding import RequestRecord

logger = logging.getLogger(__name__)

_REDACTED = "***REDACTED***"
_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}
_SENSITIVE_BODY_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "api_key"}


def _redact_headers(headers: dict) -> dict:
    return {
        k: (_REDACTED if k.lower() in _SENSITIVE_HEADER_NAMES else v)
        for k, v in headers.items()
    }


def _redact_body(body: Any) -> Any:
    if isinstance(body, dict):
        return {
            k: (_REDACTED if k.lower() in _SENSITIVE_BODY_KEYS else _redact_body(v))
            for k, v in body.items()
        }
    if isinstance(body, list):
        return [_redact_body(item) for item in body]
    return body


class RequestEngine:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def execute(
        self,
        operation: Operation,
        principal: Principal,
        identifier_bindings: Optional[dict[str, Any]] = None,
        extra_body_fields: Optional[dict[str, Any]] = None,
    ) -> RequestRecord:
        identifier_bindings = identifier_bindings or {}
        if operation.api_type == ApiType.REST:
            return self._execute_rest(
                operation, principal, identifier_bindings, extra_body_fields or {}
            )
        return self._execute_graphql(operation, principal, identifier_bindings)

    # -- REST ------------------------------------------------------------

    def _execute_rest(
        self,
        operation: Operation,
        principal: Principal,
        identifier_bindings: dict[str, Any],
        extra_body_fields: dict[str, Any],
    ) -> RequestRecord:
        path = operation.path_template or ""
        query_params: dict[str, Any] = {}
        body: dict[str, Any] = dict(extra_body_fields)
        headers: dict[str, str] = {}

        for param in operation.parameters:
            value = identifier_bindings.get(param.name, param.example)
            if value is None:
                continue
            if param.location == ParameterLocation.PATH:
                path = path.replace("{" + param.name + "}", str(value))
            elif param.location == ParameterLocation.QUERY:
                query_params[param.name] = value
            elif param.location == ParameterLocation.HEADER:
                headers[param.name] = str(value)
            elif param.location == ParameterLocation.BODY and param.json_path:
                _set_dotted(body, param.json_path, value)

        base_url = operation.base_url or ""
        url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path.lstrip("/"))

        request_kwargs: dict[str, Any] = {"headers": headers, "params": query_params}
        if body and operation.http_method and operation.http_method.value in (
            "POST",
            "PUT",
            "PATCH",
        ):
            request_kwargs["json"] = body

        request_kwargs = principal.apply_auth(request_kwargs)

        start = time.monotonic()
        try:
            resp = principal.session.request(
                operation.http_method.value if operation.http_method else "GET",
                url,
                timeout=self.timeout,
                **request_kwargs,
            )
        except requests.RequestException as exc:
            logger.warning("Request failed for %s %s: %s", operation.describe(), principal.label, exc)
            return RequestRecord(
                method=operation.http_method.value if operation.http_method else None,
                url=url,
                headers=_redact_headers(request_kwargs.get("headers", {})),
                body=_redact_body(request_kwargs.get("json")),
                status_code=None,
                response_body={"error": str(exc)},
            )
        elapsed_ms = (time.monotonic() - start) * 1000

        response_body: Any
        try:
            response_body = resp.json()
        except ValueError:
            response_body = resp.text[:4096]

        return RequestRecord(
            method=operation.http_method.value if operation.http_method else None,
            url=url,
            headers=_redact_headers(request_kwargs.get("headers", {})),
            body=_redact_body(request_kwargs.get("json")),
            status_code=resp.status_code,
            response_body=response_body,
            response_headers=dict(resp.headers),
            elapsed_ms=elapsed_ms,
        )

    # -- GraphQL -----------------------------------------------------------

    def _execute_graphql(
        self,
        operation: Operation,
        principal: Principal,
        identifier_bindings: dict[str, Any],
    ) -> RequestRecord:
        if operation.graphql_selection is None:
            raise ValueError(f"Operation {operation.operation_id} has no selection tree")

        query, variables = build_query(
            operation_kind=operation.graphql_operation_kind or "query",
            root_field=operation.graphql_operation_name or "",
            root_selection=operation.graphql_selection,
            argument_values=identifier_bindings,
        )

        request_kwargs: dict[str, Any] = {"headers": {}}
        request_kwargs = principal.apply_auth(request_kwargs)

        start = time.monotonic()
        try:
            resp = principal.session.post(
                operation.base_url,
                json={"query": query, "variables": variables},
                timeout=self.timeout,
                **request_kwargs,
            )
        except requests.RequestException as exc:
            logger.warning("GraphQL request failed for %s: %s", operation.operation_id, exc)
            return RequestRecord(
                method="POST",
                url=operation.base_url or "",
                headers=_redact_headers(request_kwargs.get("headers", {})),
                graphql_query=query,
                graphql_variables=variables,
                status_code=None,
                response_body={"error": str(exc)},
            )
        elapsed_ms = (time.monotonic() - start) * 1000

        try:
            response_body = resp.json()
        except ValueError:
            response_body = resp.text[:4096]

        return RequestRecord(
            method="POST",
            url=operation.base_url or "",
            headers=_redact_headers(request_kwargs.get("headers", {})),
            graphql_query=query,
            graphql_variables=variables,
            status_code=resp.status_code,
            response_body=response_body,
            response_headers=dict(resp.headers),
            elapsed_ms=elapsed_ms,
        )


def _set_dotted(obj: dict, dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    node = obj
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
