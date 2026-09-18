"""Command-line entry point.

Usage:
    bola-scan --config scan_config.yaml
    bola-scan --mode openapi --source spec.json --base-url http://target/ \\
        --config scan_config.yaml

The scan config carries principals/credentials; --mode/--source/--base-url
on the command line, when given, override the discovery section of the
config file so the same principal setup can be reused across targets.
"""

from __future__ import annotations

import argparse
import logging
import sys

from bola_framework.config import load_scan_config
from bola_framework.models.finding import BolaClassification
from bola_framework.reporting import write_json_report, write_markdown_report
from bola_framework.scanner import Scanner


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bola-scan",
        description=(
            "Black-box, cross-session BOLA identification and exploitation "
            "framework for REST and GraphQL APIs."
        ),
    )
    parser.add_argument(
        "--config", required=True, help="Path to the YAML/JSON scan configuration file."
    )
    parser.add_argument(
        "--mode",
        choices=["openapi", "graphql", "auto"],
        help="Override the discovery mode from the config file.",
    )
    parser.add_argument(
        "--source",
        help="Override the discovery source (OpenAPI path/URL, GraphQL endpoint, or auto-discovery start URL).",
    )
    parser.add_argument("--base-url", help="Override the REST base URL.")
    parser.add_argument(
        "--json-out", help="Override the JSON report output path."
    )
    parser.add_argument(
        "--markdown-out", help="Override the Markdown report output path."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("bola_framework.cli")

    config = load_scan_config(args.config)
    if args.mode:
        config.discovery.mode = args.mode
    if args.source:
        config.discovery.source = args.source
    if args.base_url:
        config.discovery.base_url = args.base_url
    if args.json_out:
        config.output_json = args.json_out
    if args.markdown_out:
        config.output_markdown = args.markdown_out

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
    logger.info("Reports written to %s and %s", config.output_json, config.output_markdown)

    return 1 if confirmed else 0


if __name__ == "__main__":
    sys.exit(main())
