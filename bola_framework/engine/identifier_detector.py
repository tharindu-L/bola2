"""Generic object identifier detection.

Flags Operation parameters (REST path/query/body, GraphQL arguments) that are
plausibly object identifiers, using contextual signals rather than treating
every number or string as an identifier. No target-specific field names are
hard-coded; the signal list below is drawn from cross-cutting naming and
shape conventions common to REST and GraphQL APIs in general.
"""

from __future__ import annotations

import re
from dataclasses import replace

from bola_framework.models import (
    ApiType,
    CandidateIdentifier,
    GraphQLSelection,
    Operation,
    Parameter,
    ParameterLocation,
)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INTEGER_RE = re.compile(r"^\d+$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")
_OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")

# Name fragments that, combined with a plausible value shape, suggest an
# object/resource identifier rather than an unrelated scalar parameter.
_NAME_SIGNAL_FRAGMENTS = (
    "id",
    "uuid",
    "guid",
    "identifier",
    "ref",
    "key",
    "number",
    "code",
)

# Name fragments that suggest ownership/principal identifiers specifically
# (a stronger signal than a generic object id, useful to ownership.py).
_OWNER_NAME_FRAGMENTS = ("user", "owner", "account", "customer", "author", "creator")


def _name_matches_fragment(name: str, fragments: tuple[str, ...]) -> list[str]:
    lowered = name.lower()
    return [f for f in fragments if f in lowered]


def _classify_shape(value) -> tuple[str, float]:
    """Return (shape_label, base_confidence) for a value's apparent identifier shape."""
    if value is None:
        return "unknown", 0.0
    text = str(value)
    if _UUID_RE.match(text):
        return "uuid", 0.9
    if _INTEGER_RE.match(text):
        return "integer", 0.55
    if _SLUG_RE.match(text):
        return "slug", 0.5
    if _OPAQUE_TOKEN_RE.match(text):
        return "opaque", 0.45
    return "unknown", 0.15


def detect_identifiers(operation: Operation) -> list[CandidateIdentifier]:
    """Populate and return candidate identifiers for a single operation."""
    candidates: list[CandidateIdentifier] = []

    for param in operation.parameters:
        candidates.extend(_evaluate_parameter(param))

    if operation.api_type == ApiType.GRAPHQL and operation.graphql_selection:
        candidates.extend(_evaluate_graphql_tree(operation.graphql_selection))

    operation.candidate_identifiers = candidates
    return candidates


def _evaluate_parameter(param: Parameter) -> list[CandidateIdentifier]:
    results: list[CandidateIdentifier] = []

    shape, shape_confidence = _classify_shape(param.example)
    name_signals = _name_matches_fragment(param.name, _NAME_SIGNAL_FRAGMENTS)

    location_bonus = {
        ParameterLocation.PATH: 0.35,
        ParameterLocation.QUERY: 0.2,
        ParameterLocation.BODY: 0.15,
        ParameterLocation.GRAPHQL_ARGUMENT: 0.3,
        ParameterLocation.GRAPHQL_VARIABLE: 0.3,
    }.get(param.location, 0.05)

    confidence = shape_confidence + location_bonus
    signals = []
    if shape != "unknown":
        signals.append(f"value-shape:{shape}")
    if name_signals:
        confidence += 0.2
        signals.append(f"name-signal:{','.join(name_signals)}")
    if param.location == ParameterLocation.PATH and (name_signals or shape != "unknown"):
        confidence += 0.1
        signals.append("path-segment")

    # A parameter with no name signal AND no plausible shape is not a candidate.
    if not name_signals and shape == "unknown":
        return results

    confidence = min(1.0, confidence)
    if confidence < 0.3:
        return results

    results.append(
        CandidateIdentifier(
            parameter_name=param.name,
            location=param.location,
            json_path=param.json_path,
            value_seen=param.example,
            id_shape=shape if shape != "unknown" else None,
            confidence=confidence,
            signals=signals,
        )
    )
    return results


def _evaluate_graphql_tree(
    node: GraphQLSelection, path_prefix: str = ""
) -> list[CandidateIdentifier]:
    results: list[CandidateIdentifier] = []
    current_path = f"{path_prefix}.{node.field_name}" if path_prefix else node.field_name

    for arg in node.arguments:
        arg_results = _evaluate_parameter(arg)
        for candidate in arg_results:
            candidate.json_path = f"{current_path}.{candidate.parameter_name}"
        results.extend(arg_results)

    for child in node.selections:
        results.extend(_evaluate_graphql_tree(child, current_path))

    return results


def is_owner_signal(name: str) -> bool:
    """True if a parameter/field name looks like it denotes a principal
    (user/account/owner) rather than a generic object id. Used by ownership.py
    as one contextual signal among several -- never as proof on its own.
    """
    return bool(_name_matches_fragment(name, _OWNER_NAME_FRAGMENTS))
