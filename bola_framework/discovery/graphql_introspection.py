"""GraphQL introspection discovery backend.

Issues the standard introspection query against a target endpoint and turns
the returned schema into Operations, one per query/mutation root field, with
a first-class nested GraphQLSelection tree built up to a bounded depth so
nested-object BOLA (the dissertation's headline contribution) can be tested.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from bola_framework.discovery.base import Discoverer
from bola_framework.models import (
    ApiType,
    DiscoverySource,
    GraphQLSelection,
    Operation,
    OperationType,
    Parameter,
    ParameterLocation,
)

logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { ...TypeRef } }
        type { ...TypeRef }
      }
      inputFields { name type { ...TypeRef } }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
  }
}
"""

_MUTATION_KEYWORDS = ("create", "add", "update", "edit", "delete", "remove", "set")


def _unwrap_type(type_ref: dict) -> tuple[str, bool, Optional[str]]:
    """Return (base_type_name, is_list, base_kind) by unwrapping NON_NULL/LIST wrappers."""
    is_list = False
    kind = type_ref.get("kind")
    name = type_ref.get("name")
    node = type_ref
    while node:
        if node.get("kind") == "LIST":
            is_list = True
        if node.get("name"):
            name = node["name"]
            kind = node.get("kind")
        node = node.get("ofType")
    return name, is_list, kind


class GraphQLIntrospectionDiscoverer(Discoverer):
    def __init__(
        self,
        endpoint: str,
        headers: Optional[dict] = None,
        max_selection_depth: int = 4,
        timeout: float = 15.0,
    ):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.max_selection_depth = max_selection_depth
        self.timeout = timeout
        self._types_by_name: dict = {}

    def _fetch_schema(self) -> dict:
        resp = requests.post(
            self.endpoint,
            json={"query": _INTROSPECTION_QUERY},
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        if "errors" in payload and not payload.get("data"):
            raise RuntimeError(f"Introspection failed: {payload['errors']}")
        return payload["data"]["__schema"]

    def discover(self) -> list[Operation]:
        schema = self._fetch_schema()
        self._types_by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

        operations: list[Operation] = []
        query_type_name = (schema.get("queryType") or {}).get("name")
        mutation_type_name = (schema.get("mutationType") or {}).get("name")

        if query_type_name:
            operations.extend(self._operations_for_root(query_type_name, "query"))
        if mutation_type_name:
            operations.extend(self._operations_for_root(mutation_type_name, "mutation"))

        logger.info("GraphQL introspection discovery produced %d operations", len(operations))
        return operations

    def _operations_for_root(self, root_type_name: str, kind: str) -> list[Operation]:
        root_type = self._types_by_name.get(root_type_name, {})
        ops: list[Operation] = []
        for field_def in root_type.get("fields", []) or []:
            name = field_def["name"]
            args = self._args_to_parameters(field_def.get("args", []))
            return_type_name, is_list, return_kind = _unwrap_type(field_def.get("type", {}))
            selection = self._build_selection(
                field_name=name,
                return_type_name=return_type_name,
                return_kind=return_kind,
                is_list=is_list,
                depth=0,
            )
            operation_type = self._classify_operation(kind, name)
            ops.append(
                Operation(
                    operation_id=f"{kind}.{name}",
                    api_type=ApiType.GRAPHQL,
                    operation_type=operation_type,
                    source=DiscoverySource.GRAPHQL_INTROSPECTION,
                    base_url=self.endpoint,
                    graphql_operation_name=name,
                    graphql_operation_kind=kind,
                    graphql_selection=selection,
                    parameters=args,
                )
            )
        return ops

    @staticmethod
    def _classify_operation(kind: str, field_name: str) -> OperationType:
        if kind == "query":
            return OperationType.READ
        lowered = field_name.lower()
        if any(k in lowered for k in ("delete", "remove")):
            return OperationType.DELETE
        if any(k in lowered for k in ("create", "add")):
            return OperationType.CREATE
        if any(k in lowered for k in ("update", "edit", "set")):
            return OperationType.UPDATE
        return OperationType.UNKNOWN

    def _args_to_parameters(self, args: list[dict]) -> list[Parameter]:
        params = []
        for arg in args:
            type_name, is_list, _kind = _unwrap_type(arg.get("type", {}))
            params.append(
                Parameter(
                    name=arg["name"],
                    location=ParameterLocation.GRAPHQL_ARGUMENT,
                    type_hint=type_name,
                    required=arg.get("type", {}).get("kind") == "NON_NULL",
                )
            )
        return params

    def _build_selection(
        self,
        field_name: str,
        return_type_name: Optional[str],
        return_kind: Optional[str],
        is_list: bool,
        depth: int,
        visited: Optional[set] = None,
    ) -> GraphQLSelection:
        visited = set(visited) if visited else set()
        selection = GraphQLSelection(
            field_name=field_name,
            return_type=return_type_name,
            is_list=is_list,
        )

        if depth >= self.max_selection_depth or not return_type_name:
            return selection
        if return_type_name in visited:
            return selection  # break cycles (e.g. User -> Posts -> User)
        if return_kind not in ("OBJECT", "INTERFACE"):
            return selection

        type_def = self._types_by_name.get(return_type_name)
        if not type_def:
            return selection

        visited.add(return_type_name)
        for child_field in type_def.get("fields", []) or []:
            child_type_name, child_is_list, child_kind = _unwrap_type(
                child_field.get("type", {})
            )
            child_args = self._args_to_parameters(child_field.get("args", []))
            child_selection = self._build_selection(
                field_name=child_field["name"],
                return_type_name=child_type_name,
                return_kind=child_kind,
                is_list=child_is_list,
                depth=depth + 1,
                visited=visited,
            )
            child_selection.arguments = child_args
            selection.selections.append(child_selection)

        return selection
