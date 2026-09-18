"""Turns a list of Findings into reproducible JSON/Markdown reports.

Secrets are already redacted at the RequestRecord level (see
engine.request_engine), but this module re-checks headers/bodies defensively
before writing anything to disk.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from bola_framework.models.finding import BolaClassification, Finding

_SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "authorization",
    "cookie",
    "set-cookie",
}


def _scrub(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: ("***REDACTED***" if k.lower() in _SENSITIVE_KEYS else _scrub(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def write_json_report(findings: list[Finding], output_path: str) -> None:
    payload = {
        "finding_count": len(findings),
        "confirmed_bola_count": sum(
            1 for f in findings if f.classification == BolaClassification.CONFIRMED_BOLA
        ),
        "findings": [_scrub(f.to_dict()) for f in findings],
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def write_markdown_report(findings: list[Finding], output_path: str) -> None:
    lines = ["# BOLA Scan Report", ""]
    confirmed = [f for f in findings if f.classification == BolaClassification.CONFIRMED_BOLA]
    lines.append(f"**Total test cases evaluated:** {len(findings)}")
    lines.append(f"**Confirmed BOLA findings:** {len(confirmed)}")
    lines.append("")

    by_classification: dict[str, list[Finding]] = {}
    for f in findings:
        by_classification.setdefault(f.classification.value, []).append(f)

    for classification, group in by_classification.items():
        lines.append(f"## {classification} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.append(f"### {finding.finding_id} -- {finding.operation_description}")
            lines.append(f"- API type: `{finding.api_type}`")
            lines.append(f"- Confidence: `{finding.confidence.value}`")
            lines.append(f"- Object identifier: `{finding.object_identifier}`")
            if finding.graphql_nested_path:
                lines.append(f"- GraphQL nested path: `{finding.graphql_nested_path}`")
            lines.append(f"- {finding.user_a_label} vs {finding.user_b_label}")
            lines.append(f"- Rationale: {finding.evidence.rationale}")
            if finding.evidence.ownership_signals:
                lines.append("- Ownership evidence:")
                for sig in finding.evidence.ownership_signals:
                    lines.append(f"  - {sig}")
            if finding.evidence.object_specific_fields_disclosed:
                lines.append(
                    f"- Object-specific fields disclosed: "
                    f"{', '.join(finding.evidence.object_specific_fields_disclosed)}"
                )
            if finding.baseline_request:
                lines.append(
                    f"- Baseline request: `{finding.baseline_request.method} "
                    f"{finding.baseline_request.url}` -> {finding.baseline_request.status_code}"
                )
            if finding.cross_user_request:
                lines.append(
                    f"- Cross-user request: `{finding.cross_user_request.method} "
                    f"{finding.cross_user_request.url}` -> {finding.cross_user_request.status_code}"
                )
            lines.append(f"- Timestamp: {finding.timestamp}")
            lines.append("")

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
