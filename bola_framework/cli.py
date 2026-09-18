"""Command-line entry point.

Two ways to drive a scan:

1. Config file (recommended for repeat runs against the same target):

    bola-scan scan --config scan_config.yaml

2. Direct flags (quick one-off runs, no YAML file needed):

    python cli.py scan --target http://192.168.8.142:3000 \\
        --user-a usera@test.com --pass-a "Password1!" \\
        --user-b userb@test.com --pass-b "Password2!" \\
        --id-a 1 --id-b 2 \\
        --output ./juiceshop-spec-report.json -v

Direct-flag mode builds a ScanConfig in memory: --target becomes both the
REST base URL and, combined with --mode's default discovery path, the
discovery source; --user-a/--user-b + --pass-a/--pass-b become two Principals
authenticated via a login request; --id-a/--id-b seed each principal's
user_id_hint for ownership correlation. Login shape (endpoint path, payload
field names, token JSON path) defaults to common conventions and is fully
overridable via flags -- nothing about the BOLA detection pipeline itself is
target-specific.
"""

from __future__ import annotations

import argparse
import logging
import sys
from urllib.parse import urljoin

from bola_framework.auth.session_manager import AuthScheme, LoginSpec, Principal
from bola_framework.config import DiscoveryConfig, ScanConfig, load_scan_config
from bola_framework.models.finding import BolaClassification
from bola_framework.reporting import (
    print_findings_table,
    print_report_paths,
    write_json_report,
    write_markdown_report,
)
from bola_framework.scanner import Scanner

_DEFAULT_DISCOVERY_SOURCE_PATH = {
    "openapi": "/openapi.json",
    "graphql": "/graphql",
}


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bola-scan",
        description=(
            "Black-box, cross-session BOLA identification and exploitation "
            "framework for REST and GraphQL APIs."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan", help="Run a scan against a target, either from a config file or direct flags."
    )

    scan_parser.add_argument(
        "--config", help="Path to a YAML/JSON scan configuration file."
    )

    # -- direct-flag mode (no config file) --------------------------------
    scan_parser.add_argument("--target", help="Base URL of the target, e.g. http://192.168.8.142:3000")
    scan_parser.add_argument("--user-a", help="Login identifier (email/username) for principal A.")
    scan_parser.add_argument("--pass-a", help="Password for principal A.")
    scan_parser.add_argument("--user-b", help="Login identifier (email/username) for principal B.")
    scan_parser.add_argument("--pass-b", help="Password for principal B.")
    scan_parser.add_argument(
        "--id-a", help="Principal A's own known object/account id (improves ownership evidence)."
    )
    scan_parser.add_argument(
        "--id-b", help="Principal B's own known object/account id (improves ownership evidence)."
    )
    scan_parser.add_argument(
        "--mode",
        choices=["openapi", "graphql", "auto"],
        default="auto",
        help="Discovery mode when not using --config. Default: auto.",
    )
    scan_parser.add_argument(
        "--spec-source",
        help=(
            "Discovery source: OpenAPI spec path/URL, GraphQL endpoint, or auto-discovery "
            "start URL. Defaults to <target>/openapi.json, <target>/graphql, or <target> "
            "depending on --mode."
        ),
    )
    scan_parser.add_argument(
        "--login-path",
        default="/rest/user/login",
        help="Login endpoint path relative to --target. Default: /rest/user/login.",
    )
    scan_parser.add_argument(
        "--login-user-field",
        default="email",
        help="JSON field name the login endpoint expects for the identifier. Default: email.",
    )
    scan_parser.add_argument(
        "--login-pass-field",
        default="password",
        help="JSON field name the login endpoint expects for the password. Default: password.",
    )
    scan_parser.add_argument(
        "--token-json-path",
        default="authentication.token",
        help="Dotted JSON path to the auth token in the login response. Default: authentication.token.",
    )
    scan_parser.add_argument(
        "--auth-scheme",
        choices=["bearer_token", "cookie", "api_key_header"],
        default="bearer_token",
        help="How the token/cookie obtained at login is attached to subsequent requests.",
    )
    scan_parser.add_argument(
        "--no-verify-writes",
        action="store_true",
        help="Skip post-condition re-reads that verify write (update/delete) BOLA actually changed state.",
    )

    # -- shared overrides (apply in both modes) ----------------------------
    scan_parser.add_argument("--base-url", help="Override the REST base URL.")
    scan_parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds.")
    scan_parser.add_argument(
        "--output", "--json-out", dest="output", help="JSON report output path."
    )
    scan_parser.add_argument(
        "--markdown-out", help="Markdown report output path. Defaults to --output with a .md extension."
    )
    scan_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    return parser


def _config_from_flags(args: argparse.Namespace) -> ScanConfig:
    missing = [
        name
        for name, value in (
            ("--target", args.target),
            ("--user-a", args.user_a),
            ("--pass-a", args.pass_a),
            ("--user-b", args.user_b),
            ("--pass-b", args.pass_b),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            "Missing required flag(s) for direct-flag mode (no --config given): "
            + ", ".join(missing)
        )

    target = args.target.rstrip("/")
    mode = args.mode
    source = args.spec_source or (
        target + _DEFAULT_DISCOVERY_SOURCE_PATH.get(mode, "")
        if mode in _DEFAULT_DISCOVERY_SOURCE_PATH
        else target
    )

    discovery = DiscoveryConfig(
        mode=mode,
        source=source,
        graphql_endpoint=target + "/graphql" if mode == "graphql" and not args.spec_source else None,
        base_url=args.base_url or target,
    )

    login_url = urljoin(target + "/", args.login_path.lstrip("/"))
    scheme = AuthScheme(args.auth_scheme)

    principal_a = Principal(
        label="User A",
        login_spec=LoginSpec(
            scheme=scheme,
            login_url=login_url,
            login_payload={
                args.login_user_field: args.user_a,
                args.login_pass_field: args.pass_a,
            },
            token_json_path=args.token_json_path if scheme != AuthScheme.COOKIE else None,
        ),
        user_id_hint=args.id_a,
    )
    principal_b = Principal(
        label="User B",
        login_spec=LoginSpec(
            scheme=scheme,
            login_url=login_url,
            login_payload={
                args.login_user_field: args.user_b,
                args.login_pass_field: args.pass_b,
            },
            token_json_path=args.token_json_path if scheme != AuthScheme.COOKIE else None,
        ),
        user_id_hint=args.id_b,
    )

    output_json = args.output or "bola_report.json"
    output_markdown = args.markdown_out or _derive_markdown_path(output_json)

    return ScanConfig(
        discovery=discovery,
        principals=[principal_a, principal_b],
        timeout=args.timeout,
        output_json=output_json,
        output_markdown=output_markdown,
        verify_writes=not args.no_verify_writes,
    )


def _derive_markdown_path(json_path: str) -> str:
    if json_path.endswith(".json"):
        return json_path[: -len(".json")] + ".md"
    return json_path + ".md"


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("bola_framework.cli")

    if args.config:
        config = load_scan_config(args.config)
        if args.mode and args.mode != "auto":
            config.discovery.mode = args.mode
        if args.spec_source:
            config.discovery.source = args.spec_source
        if args.base_url:
            config.discovery.base_url = args.base_url
        if args.output:
            config.output_json = args.output
        if args.markdown_out:
            config.output_markdown = args.markdown_out
    else:
        config = _config_from_flags(args)

    scanner = Scanner(config)
    findings = scanner.run()

    confirmed = [f for f in findings if f.classification == BolaClassification.CONFIRMED_BOLA]
    logger.info(
        "Scan complete: %d test cases evaluated, %d confirmed BOLA findings",
        len(findings),
        len(confirmed),
    )

    write_json_report(findings, config.output_json)
    write_markdown_report(findings, config.output_markdown)

    print_findings_table(findings)
    print_report_paths(config.output_json, config.output_markdown)

    return 1 if confirmed else 0


if __name__ == "__main__":
    sys.exit(main())
