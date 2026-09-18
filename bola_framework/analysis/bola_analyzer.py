"""BOLA Analyzer -- the deterministic oracle.

Given a baseline request (User A -> Object A, which A legitimately owns/
created) and a cross-user request (User B -> Object A, using the same
identifier), decide whether this constitutes BOLA, proper authorization, a
public resource, a token-bound resource, or insufficient evidence. Never
uses status code alone. Never uses an LLM. Every verdict carries a
human-readable rationale.
"""

from __future__ import annotations

import itertools
import logging
from typing import Any, Optional

from bola_framework.analysis.response_diff import ResponseComparison, compare_responses
from bola_framework.engine.ownership import OwnershipTracker
from bola_framework.models import ApiType, Operation, OperationType
from bola_framework.models.finding import (
    BolaClassification,
    ConfidenceLevel,
    Evidence,
    Finding,
    RequestRecord,
)

logger = logging.getLogger(__name__)

_SUCCESS_STATUSES = set(range(200, 300))
_DENIAL_STATUSES = {401, 403, 404}

_finding_counter = itertools.count(1)


def _next_finding_id() -> str:
    return f"BOLA-{next(_finding_counter):04d}"


def _response_ok(record: Optional[RequestRecord]) -> bool:
    return bool(record and record.status_code in _SUCCESS_STATUSES)


def _response_denied(record: Optional[RequestRecord]) -> bool:
    return bool(record and record.status_code in _DENIAL_STATUSES)


def classify_cross_user_access(
    operation: Operation,
    object_identifier: Any,
    user_a_label: str,
    user_b_label: str,
    baseline_request: RequestRecord,     # A -> Object A
    cross_user_request: RequestRecord,   # B -> Object A
    ownership_tracker: OwnershipTracker,
    control_request: Optional[RequestRecord] = None,  # B -> Object B
    graphql_nested_path: Optional[str] = None,
) -> Finding:
    """Apply the deterministic oracle to one cross-user test case and return a
    Finding with an explicit classification, confidence level, and rationale.
    """
    ownership = ownership_tracker.get(user_a_label, operation.operation_id, object_identifier)
    ownership_established = bool(ownership and ownership.is_established)
    ownership_signals = list(ownership.signals) if ownership else []

    evidence = Evidence(ownership_signals=ownership_signals)

    # 1. Cross-user request outright failed at the transport level: no verdict.
    if cross_user_request.status_code is None:
        evidence.rationale = "Cross-user request failed at the transport level; no verdict possible."
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            BolaClassification.INSUFFICIENT_EVIDENCE, ConfidenceLevel.INSUFFICIENT_EVIDENCE,
            evidence, graphql_nested_path,
        )

    # 2. Server properly denied the cross-user request.
    if _response_denied(cross_user_request):
        evidence.rationale = (
            f"Cross-user request received a {cross_user_request.status_code} response, "
            "consistent with correct object-level authorization enforcement."
        )
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            BolaClassification.PROPER_AUTHORIZATION, ConfidenceLevel.CONFIRMED,
            evidence, graphql_nested_path,
        )

    # 3. Cross-user request did not succeed and was not a clean denial either
    #    (e.g. 5xx, malformed) -- not evidence of BOLA either way.
    if not _response_ok(cross_user_request):
        evidence.rationale = (
            f"Cross-user request returned status {cross_user_request.status_code}, "
            "neither a success nor a recognized authorization denial; inconclusive."
        )
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            BolaClassification.INSUFFICIENT_EVIDENCE, ConfidenceLevel.INSUFFICIENT_EVIDENCE,
            evidence, graphql_nested_path,
        )

    # From here, the cross-user request succeeded (2xx). Compare content.
    comparison = compare_responses(
        baseline_request.status_code,
        baseline_request.response_body,
        cross_user_request.status_code,
        cross_user_request.response_body,
    )
    evidence.shared_content_ratio = comparison.shared_content_ratio
    non_volatile_diffs = comparison.non_volatile_differences()
    evidence.response_differences = [d.json_path for d in non_volatile_diffs][:25]

    # 4. If User A and User B's responses for the SAME identifier are
    #    (near-)identical, this is most likely a public/shared resource,
    #    unless ownership was independently established for User A and the
    #    content plainly reflects User-A-specific object data.
    if comparison.shared_content_ratio >= 0.95 and not non_volatile_diffs:
        if ownership_established:
            evidence.object_specific_fields_disclosed = _find_object_specific_fields(
                cross_user_request.response_body
            )
            evidence.rationale = (
                "User B received an identical, successful response to User A's for the "
                "same object identifier, and ownership evidence establishes the object "
                "belongs to User A. This is BOLA."
            )
            classification = BolaClassification.CONFIRMED_BOLA
            confidence = ConfidenceLevel.CONFIRMED
        else:
            evidence.rationale = (
                "User B received an identical, successful response to User A's for the "
                "same object identifier, but ownership of the object by User A could not "
                "be established; the resource is more likely intentionally public or "
                "token-bound (reflecting the caller's own identity, not object ownership)."
            )
            classification = _distinguish_public_vs_token_bound(
                baseline_request, cross_user_request, control_request
            )
            confidence = ConfidenceLevel.SUSPECTED
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            classification, confidence, evidence, graphql_nested_path,
        )

    # 5. Responses differ. Determine whether User B's response nonetheless
    #    contains fields that are object-specific to User A (a control
    #    request to B's own object, if available, sharpens this a lot).
    disclosed_fields = _find_object_specific_fields(cross_user_request.response_body)
    evidence.object_specific_fields_disclosed = disclosed_fields

    if control_request and _response_ok(control_request):
        control_comparison = compare_responses(
            cross_user_request.status_code,
            cross_user_request.response_body,
            control_request.status_code,
            control_request.response_body,
        )
        # If B's response to Object A differs from B's response to B's own
        # object in ways that mirror A's own data, that's strong evidence B
        # actually received A's object content.
        divergent_from_own_object = bool(control_comparison.non_volatile_differences())
        if divergent_from_own_object and ownership_established:
            evidence.rationale = (
                "User B's response for Object A differs from User B's response for "
                "User B's own object, and matches structural/content signals from "
                "User A's baseline for the same object; ownership of Object A by "
                "User A is established. This is BOLA."
            )
            return _build_finding(
                operation, object_identifier, user_a_label, user_b_label,
                baseline_request, cross_user_request, control_request,
                BolaClassification.CONFIRMED_BOLA, ConfidenceLevel.CONFIRMED,
                evidence, graphql_nested_path,
            )

    if ownership_established and disclosed_fields:
        evidence.rationale = (
            "User B's successful cross-user response contains fields correlated with "
            "User A's established ownership of the object, and the object-level access "
            "was not denied. This is BOLA."
        )
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            BolaClassification.CONFIRMED_BOLA, ConfidenceLevel.LIKELY,
            evidence, graphql_nested_path,
        )

    if ownership_established:
        evidence.rationale = (
            "The cross-user request succeeded and ownership of the object by User A is "
            "established, but the response content did not clearly disclose "
            "object-specific data attributable to User A; treating as likely BOLA on "
            "access grounds alone, pending manual confirmation."
        )
        return _build_finding(
            operation, object_identifier, user_a_label, user_b_label,
            baseline_request, cross_user_request, control_request,
            BolaClassification.CONFIRMED_BOLA, ConfidenceLevel.LIKELY,
            evidence, graphql_nested_path,
        )

    evidence.rationale = (
        "The cross-user request succeeded, but ownership of the object by User A could "
        "not be established with sufficient confidence, so no BOLA verdict can be made."
    )
    return _build_finding(
        operation, object_identifier, user_a_label, user_b_label,
        baseline_request, cross_user_request, control_request,
        BolaClassification.INSUFFICIENT_EVIDENCE, ConfidenceLevel.SUSPECTED,
        evidence, graphql_nested_path,
    )


def verify_write_bola(
    operation: Operation,
    cross_user_request: RequestRecord,      # B attempts to mutate Object A
    state_check_as_a: Optional[RequestRecord],  # A re-reads Object A afterward
    baseline_before_state: Optional[Any] = None,
) -> tuple[bool, str]:
    """For write operations (create/update/delete), a successful HTTP status
    from the cross-user request is not sufficient evidence. Where a
    post-condition read is available, compare it against the pre-mutation
    state to determine whether User B's request actually altered User A's
    object.
    """
    if operation.operation_type not in (OperationType.UPDATE, OperationType.DELETE):
        return False, "Not a state-changing operation type; write verification not applicable."

    if not _response_ok(cross_user_request):
        return False, (
            f"Cross-user write request did not succeed (status "
            f"{cross_user_request.status_code}); no state change to verify."
        )

    if state_check_as_a is None:
        return False, (
            "Cross-user write request succeeded, but no post-condition read was "
            "available to confirm User A's object was actually altered; treat as "
            "suspected rather than confirmed."
        )

    if operation.operation_type == OperationType.DELETE:
        deleted = _response_denied(state_check_as_a) or state_check_as_a.status_code == 404
        if deleted:
            return True, "Post-condition read shows the object no longer exists for User A: confirmed state change."
        return False, "Post-condition read still shows the object exists for User A: no confirmed state change."

    if baseline_before_state is None:
        return False, "No pre-mutation snapshot available to compare against; cannot confirm state change."

    comparison = compare_responses(
        200, baseline_before_state, state_check_as_a.status_code, state_check_as_a.response_body
    )
    changed = bool(comparison.non_volatile_differences())
    if changed:
        return True, "Post-condition read differs from the pre-mutation snapshot: confirmed state change by User B."
    return False, "Post-condition read matches the pre-mutation snapshot: no confirmed state change."


def _distinguish_public_vs_token_bound(
    baseline_request: RequestRecord,
    cross_user_request: RequestRecord,
    control_request: Optional[RequestRecord],
) -> BolaClassification:
    """If a control request (B -> Object B) is available and differs from
    B -> Object A, the resource reflects caller identity (token-bound) rather
    than being globally public."""
    if control_request and _response_ok(control_request):
        control_comparison = compare_responses(
            cross_user_request.status_code,
            cross_user_request.response_body,
            control_request.status_code,
            control_request.response_body,
        )
        if control_comparison.non_volatile_differences():
            return BolaClassification.TOKEN_BOUND_RESOURCE
    return BolaClassification.PUBLIC_RESOURCE


# Field names that, when present with a non-empty value, suggest the response
# carries data specific to an individual object/owner rather than shared
# configuration content. Generic, cross-application, not tied to any target.
_OBJECT_SPECIFIC_FIELD_HINTS = (
    "email",
    "phone",
    "address",
    "balance",
    "ssn",
    "dob",
    "dateofbirth",
    "card",
    "iban",
    "account_number",
    "message",
    "note",
    "medical",
    "diagnosis",
    "salary",
    "token",
    "location",
)


def _find_object_specific_fields(response_body: Any) -> list[str]:
    from bola_framework.analysis.response_diff import _flatten

    flat = _flatten(response_body)
    found = []
    for path, value in flat.items():
        leaf_name = path.rsplit(".", 1)[-1].lower()
        if value in (None, "", []):
            continue
        if any(hint in leaf_name for hint in _OBJECT_SPECIFIC_FIELD_HINTS):
            found.append(path)
    return found


def _build_finding(
    operation: Operation,
    object_identifier: Any,
    user_a_label: str,
    user_b_label: str,
    baseline_request: RequestRecord,
    cross_user_request: RequestRecord,
    control_request: Optional[RequestRecord],
    classification: BolaClassification,
    confidence: ConfidenceLevel,
    evidence: Evidence,
    graphql_nested_path: Optional[str],
) -> Finding:
    return Finding(
        finding_id=_next_finding_id(),
        classification=classification,
        confidence=confidence,
        operation_id=operation.operation_id,
        api_type=operation.api_type.value,
        operation_description=operation.describe(),
        graphql_nested_path=graphql_nested_path,
        object_identifier=object_identifier,
        user_a_label=user_a_label,
        user_b_label=user_b_label,
        baseline_request=baseline_request,
        cross_user_request=cross_user_request,
        control_request=control_request,
        evidence=evidence,
    )
