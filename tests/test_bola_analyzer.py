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
    tracker.record_creation("A", 1)
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
