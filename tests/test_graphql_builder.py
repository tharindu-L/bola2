from bola_framework.engine.graphql_builder import build_query
from bola_framework.models import GraphQLSelection, Parameter, ParameterLocation


def test_build_query_binds_root_argument_as_variable():
    selection = GraphQLSelection(
        field_name="user",
        arguments=[Parameter(name="id", location=ParameterLocation.GRAPHQL_ARGUMENT, type_hint="ID", required=True)],
        selections=[GraphQLSelection(field_name="id"), GraphQLSelection(field_name="email")],
    )
    query, variables = build_query("query", "user", selection, {"id": "42"})
    assert "user(id: $user_id)" in query
    assert variables == {"user_id": "42"}
    assert "email" in query


def test_build_query_handles_nested_selection():
    inner = GraphQLSelection(field_name="owner", selections=[GraphQLSelection(field_name="email")])
    selection = GraphQLSelection(field_name="order", selections=[GraphQLSelection(field_name="id"), inner])
    query, _ = build_query("query", "order", selection, {})
    assert "owner { email }" in query
