from bola_framework.analysis.response_diff import compare_responses


def test_identical_responses_have_full_shared_ratio():
    body = {"id": 1, "name": "shared config value"}
    comparison = compare_responses(200, body, 200, body)
    assert comparison.shared_content_ratio == 1.0
    assert not comparison.non_volatile_differences()


def test_differing_object_specific_field_detected():
    body_a = {"id": 1, "email": "a@example.test"}
    body_b = {"id": 1, "email": "b@example.test"}
    comparison = compare_responses(200, body_a, 200, body_b)
    diffs = comparison.non_volatile_differences()
    assert any(d.json_path == "email" for d in diffs)


def test_volatile_fields_excluded_from_non_volatile_differences():
    body_a = {"id": 1, "requestId": "abc"}
    body_b = {"id": 1, "requestId": "xyz"}
    comparison = compare_responses(200, body_a, 200, body_b)
    assert comparison.non_volatile_differences() == []


def test_nested_field_difference_detected():
    body_a = {"data": {"object": {"owner": {"email": "a@example.test"}}}}
    body_b = {"data": {"object": {"owner": {"email": "b@example.test"}}}}
    comparison = compare_responses(200, body_a, 200, body_b)
    diffs = [d.json_path for d in comparison.non_volatile_differences()]
    assert "data.object.owner.email" in diffs
