from bola_framework.analysis.bola_analyzer import classify_cross_user_access
from bola_framework.engine.ownership import OwnershipTracker
from bola_framework.models import ApiType, DiscoverySource, HttpMethod, Operation, OperationType
from bola_framework.models.finding import BolaClassification, RequestRecord


def _op():
    return Operation(
        operation_id="get_order",
        api_type=ApiType.REST,
        operation_type=OperationType.READ,
        source=DiscoverySource.OPENAPI,
        http_method=HttpMethod.GET,
        path_template="/api/orders/{id}",
    )


def test_proper_authorization_denied_is_classified_correctly():
    tracker = OwnershipTracker()
    baseline = RequestRecord(method="GET", url="u", status_code=200, response_body={"id": 1, "email": "a@x.test"})
    cross = RequestRecord(method="GET", url="u", status_code=403, response_body={"error": "forbidden"})
    finding = classify_cross_user_access(
        _op(), object_identifier=1, user_a_label="A", user_b_label="B",
        baseline_request=baseline, cross_user_request=cross, ownership_tracker=tracker,
    )
    assert finding.classification == BolaClassification.PROPER_AUTHORIZATION


def test_confirmed_bola_when_ownership_established_and_data_leaked():
    tracker = OwnershipTracker()
    tracker.record_creation("A", "get_order", 1)
    baseline = RequestRecord(method="GET", url="u", status_code=200, response_body={"id": 1, "email": "a@x.test"})
    cross = RequestRecord(method="GET", url="u", status_code=200, response_body={"id": 1, "email": "a@x.test"})
    finding = classify_cross_user_access(
        _op(), object_identifier=1, user_a_label="A", user_b_label="B",
        baseline_request=baseline, cross_user_request=cross, ownership_tracker=tracker,
    )
    assert finding.classification == BolaClassification.CONFIRMED_BOLA
    assert finding.confidence.value == "confirmed"


def test_insufficient_evidence_when_ownership_unestablished_and_content_differs():
    tracker = OwnershipTracker()
    baseline = RequestRecord(method="GET", url="u", status_code=200, response_body={"id": 1, "email": "a@x.test"})
    cross = RequestRecord(method="GET", url="u", status_code=200, response_body={"id": 1, "note": "generic"})
    finding = classify_cross_user_access(
        _op(), object_identifier=1, user_a_label="A", user_b_label="B",
        baseline_request=baseline, cross_user_request=cross, ownership_tracker=tracker,
    )
    assert finding.classification == BolaClassification.INSUFFICIENT_EVIDENCE


def test_public_resource_when_identical_and_no_ownership_evidence():
    tracker = OwnershipTracker()
    body = {"id": 1, "name": "Public Config"}
    baseline = RequestRecord(method="GET", url="u", status_code=200, response_body=body)
    cross = RequestRecord(method="GET", url="u", status_code=200, response_body=body)
    finding = classify_cross_user_access(
        _op(), object_identifier=1, user_a_label="A", user_b_label="B",
        baseline_request=baseline, cross_user_request=cross, ownership_tracker=tracker,
    )
    assert finding.classification in (
        BolaClassification.PUBLIC_RESOURCE,
        BolaClassification.TOKEN_BOUND_RESOURCE,
    )


def test_ownership_does_not_leak_across_unrelated_operations():
    """Regression test for a live false positive: the same literal identifier
    string ("deluxe-membership") appeared as a real per-request identifier
    against one operation (a /rest/{param} config lookup) and, coincidentally,
    as a static SPA route name against a totally unrelated operation
    (a top-level /{param} page). Ownership evidence gathered against the
    first operation must never leak into the second.
    """
    tracker = OwnershipTracker()

    config_op = Operation(
        operation_id="auto.GET./rest/{param1}",
        api_type=ApiType.REST,
        operation_type=OperationType.READ,
        source=DiscoverySource.AUTO_DISCOVERY,
        http_method=HttpMethod.GET,
        path_template="/rest/{param1}",
    )
    spa_route_op = Operation(
        operation_id="auto.GET./{param1}",
        api_type=ApiType.REST,
        operation_type=OperationType.READ,
        source=DiscoverySource.AUTO_DISCOVERY,
        http_method=HttpMethod.GET,
        path_template="/{param1}",
    )

    # Ownership established against the config-lookup operation only.
    tracker.record_authenticated_listing("A", config_op.operation_id, "deluxe-membership")

    # A totally different operation happens to reuse the same literal string,
    # returning identical static SPA-shell HTML to both users.
    shell_html = "<html>SPA shell</html>"
    baseline = RequestRecord(method="GET", url="u", status_code=200, response_body=shell_html)
    cross = RequestRecord(method="GET", url="u", status_code=200, response_body=shell_html)

    finding = classify_cross_user_access(
        spa_route_op, object_identifier="deluxe-membership", user_a_label="A", user_b_label="B",
        baseline_request=baseline, cross_user_request=cross, ownership_tracker=tracker,
    )

    assert finding.classification != BolaClassification.CONFIRMED_BOLA
    assert finding.evidence.ownership_signals == []
