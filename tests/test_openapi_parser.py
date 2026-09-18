import json

from bola_framework.discovery.openapi_parser import OpenApiDiscoverer

_MINIMAL_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test", "version": "1.0"},
    "servers": [{"url": "http://example.test"}],
    "paths": {
        "/api/orders/{id}": {
            "get": {
                "operationId": "getOrder",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}, "example": 42}
                ],
                "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}},
            }
        },
        "/api/orders": {
            "post": {
                "operationId": "createOrder",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "customer_id": {"type": "integer", "example": 7},
                                    "items": {"type": "array", "items": {"type": "string"}},
                                },
                            }
                        }
                    }
                },
                "responses": {"201": {}},
            }
        },
    },
}


def test_openapi_parser_extracts_path_and_body_parameters(tmp_path):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_MINIMAL_SPEC))

    discoverer = OpenApiDiscoverer(source=str(spec_path))
    operations = discoverer.discover()

    assert len(operations) == 2
    get_op = next(op for op in operations if op.operation_id == "getOrder")
    assert get_op.path_template == "/api/orders/{id}"
    assert get_op.base_url == "http://example.test"
    assert any(p.name == "id" for p in get_op.parameters)

    post_op = next(op for op in operations if op.operation_id == "createOrder")
    body_param_names = {p.name for p in post_op.parameters}
    assert "customer_id" in body_param_names
