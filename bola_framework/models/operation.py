"""Unified operation model.

OpenAPI parsing, GraphQL introspection, and automatic discovery all produce
instances of `Operation`. Every downstream component (Authentication Manager,
Request Engine, Identifier/Ownership analysis, BOLA Analyzer) consumes this
single representation, regardless of which discovery mode produced it. This
is the seam described in Chapter 3 of the dissertation, formalized so that no
detection logic needs to be duplicated per API paradigm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ApiType(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"


class OperationType(str, Enum):
    """Coarse-grained BOLA-relevant classification of what an operation does."""

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    UNKNOWN = "unknown"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class DiscoverySource(str, Enum):
    """Provenance tag. Never used for detection logic branching -- reporting only."""

    OPENAPI = "openapi"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    AUTO_DISCOVERY = "auto_discovery"


class ParameterLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    GRAPHQL_ARGUMENT = "graphql_argument"
    GRAPHQL_VARIABLE = "graphql_variable"


REST_METHOD_TO_OPERATION_TYPE = {
    HttpMethod.GET: OperationType.READ,
    HttpMethod.HEAD: OperationType.READ,
    HttpMethod.OPTIONS: OperationType.READ,
    HttpMethod.POST: OperationType.CREATE,
    HttpMethod.PUT: OperationType.UPDATE,
    HttpMethod.PATCH: OperationType.UPDATE,
    HttpMethod.DELETE: OperationType.DELETE,
}


@dataclass
class Parameter:
    """A single input to an operation: REST path/query/header/body field, or a
    GraphQL argument/variable."""

    name: str
    location: ParameterLocation
    type_hint: Optional[str] = None
    required: bool = False
    example: Any = None
    # Dotted path into a nested body/selection structure, e.g. "data.object.id"
    json_path: Optional[str] = None


@dataclass
class CandidateIdentifier:
    """A parameter or field flagged by the identifier heuristic as a plausible
    object identifier. Populated by engine.identifier_detector, not by discovery.
    """

    parameter_name: str
    location: ParameterLocation
    json_path: Optional[str]
    value_seen: Any = None
    id_shape: Optional[str] = None  # "integer" | "uuid" | "slug" | "opaque"
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)


@dataclass
class GraphQLSelection:
    """A node in a GraphQL selection tree. Kept as a first-class recursive
    structure -- never flattened into a REST-like path -- so the BOLA Analyzer
    can test authorization at any depth of the query graph.
    """

    field_name: str
    alias: Optional[str] = None
    arguments: list[Parameter] = field(default_factory=list)
    return_type: Optional[str] = None
    is_list: bool = False
    selections: list["GraphQLSelection"] = field(default_factory=list)

    def walk(self):
        """Depth-first iterator over this node and all descendants."""
        yield self
        for child in self.selections:
            yield from child.walk()


@dataclass
class Operation:
    """The unified representation of a single testable API operation."""

    operation_id: str
    api_type: ApiType
    operation_type: OperationType
    source: DiscoverySource

    # REST-specific
    http_method: Optional[HttpMethod] = None
    path_template: Optional[str] = None  # e.g. "/api/users/{id}"

    # GraphQL-specific
    graphql_operation_name: Optional[str] = None  # query/mutation root field name
    graphql_operation_kind: Optional[str] = None  # "query" | "mutation"
    graphql_selection: Optional[GraphQLSelection] = None

    # Shared
    base_url: Optional[str] = None
    parameters: list[Parameter] = field(default_factory=list)
    request_body_schema: dict = field(default_factory=dict)
    response_schema: dict = field(default_factory=dict)
    requires_auth: bool = True
    dependencies: list[str] = field(default_factory=list)  # operation_ids this depends on
    candidate_identifiers: list[CandidateIdentifier] = field(default_factory=list)
    discovery_confidence: float = 1.0  # 1.0 for spec-derived; <1.0 for auto-discovered
    tags: list[str] = field(default_factory=list)
    raw_metadata: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.api_type == ApiType.REST:
            return f"{self.http_method.value} {self.path_template}"
        return f"{self.graphql_operation_kind} {self.graphql_operation_name}"
