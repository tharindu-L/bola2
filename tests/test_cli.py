from bola_framework.cli import _build_arg_parser, _config_from_flags


def _parse(argv):
    parser = _build_arg_parser()
    return parser.parse_args(argv)


def test_direct_flags_build_valid_scan_config():
    args = _parse(
        [
            "scan",
            "--target", "http://192.168.8.142:3000",
            "--user-a", "usera@test.com",
            "--pass-a", "Password1!",
            "--user-b", "userb@test.com",
            "--pass-b", "Password2!",
            "--id-a", "1",
            "--id-b", "2",
            "--output", "./juiceshop-spec-report.json",
            "-v",
        ]
    )
    config = _config_from_flags(args)

    assert config.discovery.mode == "auto"
    assert config.discovery.base_url == "http://192.168.8.142:3000"
    assert config.output_json == "./juiceshop-spec-report.json"
    assert config.output_markdown == "./juiceshop-spec-report.md"
    assert len(config.principals) == 2
    assert config.principals[0].label == "User A"
    assert config.principals[0].user_id_hint == "1"
    assert config.principals[0].login_spec.login_payload == {
        "email": "usera@test.com",
        "password": "Password1!",
    }
    assert config.principals[1].login_spec.login_url == "http://192.168.8.142:3000/rest/user/login"


def test_openapi_mode_defaults_source_to_openapi_json():
    args = _parse(
        [
            "scan",
            "--target", "http://target:8080",
            "--mode", "openapi",
            "--user-a", "a@test.com", "--pass-a", "pa",
            "--user-b", "b@test.com", "--pass-b", "pb",
        ]
    )
    config = _config_from_flags(args)
    assert config.discovery.source == "http://target:8080/openapi.json"


def test_missing_required_flags_raises():
    args = _parse(["scan", "--target", "http://target:8080"])
    try:
        _config_from_flags(args)
        assert False, "expected SystemExit"
    except SystemExit:
        pass
