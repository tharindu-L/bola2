from bola_framework.engine.identifier_detector import detect_identifiers
from bola_framework.models import (
    ApiType,
    DiscoverySource,
    GraphQLSelection,
    HttpMethod,
    Operation,
    OperationType,
    Parameter,
    ParameterLocation,
)


def _make_rest_operation(parameters):
    return Operation(
        operation_id="op1",
        api_type=ApiType.REST,
        operation_type=OperationType.READ,
        source=DiscoverySource.OPENAPI,
        http_method=HttpMethod.GET,
        path_template="/api/things/{id}",
        parameters=parameters,
    )


def test_numeric_path_identifier_detected():
    op = _make_rest_operation(
        [Parameter(name="id", location=ParameterLocation.PATH, example="482", type_hint="integer")]
    )
    candidates = detect_identifiers(op)
    assert any(c.parameter_name == "id" and c.id_shape == "integer" for c in candidates)
    assert candidates[0].confidence > 0.5


def test_uuid_path_identifier_detected_with_high_confidence():
    op = _make_rest_operation(
        [
            Parameter(
                name="order_id",
                location=ParameterLocation.PATH,
                example="550e8400-e29b-41d4-a716-446655440000",
            )
        ]
    )
    candidates = detect_identifiers(op)
    assert candidates
    assert candidates[0].id_shape == "uuid"
    assert candidates[0].confidence > 0.8


def test_query_identifier_detected():
    op = _make_rest_operation(
        [Parameter(name="object", location=ParameterLocation.QUERY, example="99")]
    )
    candidates = detect_identifiers(op)
    assert any(c.parameter_name == "object" for c in candidates)


def test_nested_body_identifier_detected_via_json_path():
    op = _make_rest_operation(
        [
            Parameter(
                name="id",
                location=ParameterLocation.BODY,
                example="42",
                json_path="data.object.id",
            )
        ]
    )
    candidates = detect_identifiers(op)
    assert any(c.json_path == "data.object.id" for c in candidates)


def test_unrelated_scalar_parameter_is_not_flagged():
    op = _make_rest_operation(
        [Parameter(name="sort_order", location=ParameterLocation.QUERY, example="asc")]
    )
    candidates = detect_identifiers(op)
    assert candidates == []


def test_string_slug_identifier_detected():
    op = _make_rest_operation(
        [Parameter(name="slug", location=ParameterLocation.PATH, example="my-blog-post")]
    )
    candidates = detect_identifiers(op)
    assert any(c.id_shape == "slug" for c in candidates)


def test_graphql_argument_identifier_detected():
    leaf = GraphQLSelection(field_name="id")
    root = GraphQLSelection(
        field_name="object",
        arguments=[
            Parameter(name="id", location=ParameterLocation.GRAPHQL_ARGUMENT, example="7", required=True)
        ],
        selections=[leaf],
    )
    op = Operation(
        operation_id="query.object",
        api_type=ApiType.GRAPHQL,
        operation_type=OperationType.READ,
        source=DiscoverySource.GRAPHQL_INTROSPECTION,
        graphql_operation_kind="query",
        graphql_operation_name="object",
        graphql_selection=root,
    )
    candidates = detect_identifiers(op)
    assert any(c.parameter_name == "id" for c in candidates)
    assert candidates[0].json_path == "object.id"
