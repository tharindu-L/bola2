"""Finding / evidence models produced by the BOLA Analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"          # ownership proven, cross-user access proven
    LIKELY = "likely"                # strong evidence, one link in the chain inferred
    SUSPECTED = "suspected"          # response difference suspicious, ownership weak
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class BolaClassification(str, Enum):
    CONFIRMED_BOLA = "confirmed_bola"
    PROPER_AUTHORIZATION = "proper_authorization"
    PUBLIC_RESOURCE = "public_resource"
    TOKEN_BOUND_RESOURCE = "token_bound_resource"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class RequestRecord:
    """A redacted, reproducible record of one HTTP request/response pair."""

    method: Optional[str]
    url: str
    headers: dict = field(default_factory=dict)
    body: Any = None
    status_code: Optional[int] = None
    response_body: Any = None
    response_headers: dict = field(default_factory=dict)
    graphql_query: Optional[str] = None
    graphql_variables: Optional[dict] = None
    elapsed_ms: Optional[float] = None


@dataclass
class Evidence:
    """Why a finding was produced, in human-reviewable form."""

    ownership_signals: list[str] = field(default_factory=list)
    response_differences: list[str] = field(default_factory=list)
    shared_content_ratio: Optional[float] = None
    object_specific_fields_disclosed: list[str] = field(default_factory=list)
    state_verified: Optional[bool] = None
    rationale: str = ""


@dataclass
class Finding:
    finding_id: str
    classification: BolaClassification
    confidence: ConfidenceLevel
    operation_id: str
    api_type: str
    operation_description: str
    graphql_nested_path: Optional[str] = None

    object_identifier: Any = None
    user_a_label: str = "User A"
    user_b_label: str = "User B"

    baseline_request: Optional[RequestRecord] = None   # User A -> Object A
    cross_user_request: Optional[RequestRecord] = None  # User B -> Object A
    control_request: Optional[RequestRecord] = None     # User B -> Object B (optional)

    evidence: Evidence = field(default_factory=Evidence)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)
