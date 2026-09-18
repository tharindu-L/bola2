"""Deterministic response comparison.

Compares two JSON-shaped responses field by field, distinguishing:
  - shared/structural/configuration-level content (present and equal in both)
  - object-specific content that differs
  - content present in one response but absent from the other

This is the oracle machinery the BOLA Analyzer builds its verdicts on. No
HTTP-status-code-only shortcuts (200 != vulnerable, 403 != safe) -- status is
one input signal among several, never sufficient alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Fields whose value is expected to vary per-request/per-principal for
# legitimate reasons (timestamps, request-scoped tokens, pagination cursors)
# and therefore should not, by themselves, count as "object-specific
# disclosure" evidence. This is a narrow, generic allowlist of volatile
# metadata shapes -- not an application-specific rule.
_VOLATILE_FIELD_NAME_HINTS = (
    "timestamp",
    "requestid",
    "request_id",
    "trace",
    "nonce",
    "csrf",
    "expires",
    "issued",
    "servertime",
)


@dataclass
class FieldDiff:
    json_path: str
    in_a: bool
    in_b: bool
    value_a: Any = None
    value_b: Any = None
    equal: bool = False
    is_volatile: bool = False


@dataclass
class ResponseComparison:
    status_a: int | None
    status_b: int | None
    status_equal: bool
    field_diffs: list[FieldDiff] = field(default_factory=list)
    shared_field_count: int = 0
    differing_field_count: int = 0
    total_field_count: int = 0
    b_only_fields: list[str] = field(default_factory=list)
    a_only_fields: list[str] = field(default_factory=list)

    @property
    def shared_content_ratio(self) -> float:
        if self.total_field_count == 0:
            return 1.0
        return self.shared_field_count / self.total_field_count

    def non_volatile_differences(self) -> list[FieldDiff]:
        return [d for d in self.field_diffs if not d.equal and not d.is_volatile]


def _is_volatile(field_name: str) -> bool:
    lowered = field_name.lower()
    return any(hint in lowered for hint in _VOLATILE_FIELD_NAME_HINTS)


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (dict, list)):
                flat.update(_flatten(value, path))
            else:
                flat[path] = value
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                flat.update(_flatten(item, path))
            else:
                flat[path] = item
    else:
        flat[prefix or "$"] = node
    return flat


def compare_responses(
    status_a: int | None,
    body_a: Any,
    status_b: int | None,
    body_b: Any,
) -> ResponseComparison:
    flat_a = _flatten(body_a)
    flat_b = _flatten(body_b)

    all_paths = sorted(set(flat_a) | set(flat_b))
    diffs: list[FieldDiff] = []
    shared = 0
    differing = 0
    a_only = []
    b_only = []

    for path in all_paths:
        in_a = path in flat_a
        in_b = path in flat_b
        value_a = flat_a.get(path)
        value_b = flat_b.get(path)
        equal = in_a and in_b and value_a == value_b
        volatile = _is_volatile(path.rsplit(".", 1)[-1])

        if equal:
            shared += 1
        else:
            differing += 1
            if not in_a:
                b_only.append(path)
            if not in_b:
                a_only.append(path)

        diffs.append(
            FieldDiff(
                json_path=path,
                in_a=in_a,
                in_b=in_b,
                value_a=value_a,
                value_b=value_b,
                equal=equal,
                is_volatile=volatile,
            )
        )

    return ResponseComparison(
        status_a=status_a,
        status_b=status_b,
        status_equal=status_a == status_b,
        field_diffs=diffs,
        shared_field_count=shared,
        differing_field_count=differing,
        total_field_count=len(all_paths),
        b_only_fields=b_only,
        a_only_fields=a_only,
    )
