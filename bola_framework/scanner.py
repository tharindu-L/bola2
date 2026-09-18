"""Scan orchestrator.

Wires together: Discovery -> Authentication Manager -> Request Engine ->
Identifier Detection -> Ownership Tracking -> BOLA Analyzer -> Reporting.
This is the one place that knows about all modules; every module itself
stays decoupled from the others via the Operation/Finding models.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from bola_framework.analysis.bola_analyzer import classify_cross_user_access, verify_write_bola
from bola_framework.auth.session_manager import AuthenticationManager, Principal
from bola_framework.config import ScanConfig
from bola_framework.discovery import AutoDiscoverer, GraphQLIntrospectionDiscoverer, OpenApiDiscoverer
from bola_framework.engine.identifier_detector import detect_identifiers
from bola_framework.engine.ownership import OwnershipTracker
from bola_framework.engine.request_engine import RequestEngine
from bola_framework.models import ApiType, Operation, OperationType
from bola_framework.models.finding import Finding

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.auth_manager = AuthenticationManager(timeout=config.timeout)
        for principal in config.principals:
            self.auth_manager.register(principal)
        self.request_engine = RequestEngine(timeout=config.timeout)
        self.ownership_tracker = OwnershipTracker()

    # -- discovery -----------------------------------------------------------

    def discover_operations(self) -> list[Operation]:
        mode = self.config.discovery.mode
        if mode == "openapi":
            discoverer = OpenApiDiscoverer(
                source=self.config.discovery.source,
                base_url=self.config.discovery.base_url,
                timeout=self.config.timeout,
            )
        elif mode == "graphql":
            discoverer = GraphQLIntrospectionDiscoverer(
                endpoint=self.config.discovery.graphql_endpoint or self.config.discovery.source,
                timeout=self.config.timeout,
            )
        elif mode == "auto":
            discoverer = AutoDiscoverer(
                start_url=self.config.discovery.source,
                max_pages=self.config.discovery.max_pages,
                max_depth=self.config.discovery.max_depth,
                min_confidence=self.config.discovery.min_confidence,
                timeout=self.config.timeout,
            )
        else:
            raise ValueError(f"Unknown discovery mode: {mode}")

        operations = discoverer.discover()
        for op in operations:
            detect_identifiers(op)
        return operations

    # -- run -----------------------------------------------------------------

    def run(self) -> list[Finding]:
        self.auth_manager.authenticate_all()
        operations = self.discover_operations()
        logger.info("Discovered %d operations across all sources", len(operations))

        principals = list(self.auth_manager.principals.values())
        if len(principals) < 2:
            raise ValueError(
                "At least two principals (User A, User B) are required for "
                "cross-session BOLA testing."
            )
        user_a, user_b = principals[0], principals[1]

        findings: list[Finding] = []
        for operation in operations:
            findings.extend(self._test_operation(operation, user_a, user_b))
        return findings

    # -- per-operation test case generation -----------------------------------

    def _test_operation(
        self, operation: Operation, user_a: Principal, user_b: Principal
    ) -> list[Finding]:
        results: list[Finding] = []
        identifier_candidates = [
            c for c in operation.candidate_identifiers if c.confidence >= 0.3
        ]
        if not identifier_candidates:
            return results

        for candidate in identifier_candidates:
            finding = self._test_identifier(operation, candidate, user_a, user_b)
            if finding is not None:
                results.append(finding)
        return results

    def _test_identifier(
        self, operation: Operation, candidate, user_a: Principal, user_b: Principal
    ) -> Optional[Finding]:
        object_id = candidate.value_seen
        if object_id is None:
            return None

        binding_key = candidate.parameter_name
        bindings = {binding_key: object_id}

        # Step 1: User A legitimately accesses Object A, establishing a baseline.
        baseline = self.request_engine.execute(operation, user_a, bindings)
        if baseline.status_code not in range(200, 300):
            # Can't establish a legitimate baseline for this identifier; skip.
            return None

        self.ownership_tracker.record_authenticated_listing(user_a.label, object_id)
        self.ownership_tracker.scan_response_for_correlations(
            user_a.label, object_id, baseline.response_body, user_a.user_id_hint
        )

        # Step 2: User B attempts the same operation against the same identifier.
        cross_user = self.request_engine.execute(operation, user_b, bindings)

        # Step 3 (optional but strongly preferred): User B against User B's own
        # object, as a control baseline, if we already have one on record.
        control = self._build_control_request(operation, user_b, candidate)

        graphql_path = None
        if operation.api_type == ApiType.GRAPHQL:
            graphql_path = candidate.json_path

        finding = classify_cross_user_access(
            operation=operation,
            object_identifier=object_id,
            user_a_label=user_a.label,
            user_b_label=user_b.label,
            baseline_request=baseline,
            cross_user_request=cross_user,
            ownership_tracker=self.ownership_tracker,
            control_request=control,
            graphql_nested_path=graphql_path,
        )

        if self.config.verify_writes and operation.operation_type in (
            OperationType.UPDATE,
            OperationType.DELETE,
        ):
            self._augment_with_write_verification(operation, bindings, user_a, finding)

        return finding

    def _build_control_request(self, operation: Operation, user_b: Principal, candidate):
        """If User B has a known object of their own (user_id_hint doubling as an
        object identifier in the simplest case), issue a control request so the
        analyzer can distinguish "identical because public" from "identical
        because it disclosed A's data". Best-effort: returns None if no
        plausible control object id is available.
        """
        if not user_b.user_id_hint:
            return None
        if str(user_b.user_id_hint) == str(candidate.value_seen):
            return None
        control_bindings = {candidate.parameter_name: user_b.user_id_hint}
        return self.request_engine.execute(operation, user_b, control_bindings)

    def _augment_with_write_verification(
        self, operation: Operation, bindings: dict[str, Any], user_a: Principal, finding: Finding
    ) -> None:
        """Re-read Object A as User A after the cross-user write to confirm an
        actual state change occurred, rather than trusting the write's status
        code alone."""
        state_check = self.request_engine.execute(operation, user_a, bindings)
        changed, rationale = verify_write_bola(
            operation=operation,
            cross_user_request=finding.cross_user_request,
            state_check_as_a=state_check,
            baseline_before_state=finding.baseline_request.response_body
            if finding.baseline_request
            else None,
        )
        finding.evidence.state_verified = changed
        finding.evidence.rationale += f" | Write verification: {rationale}"
