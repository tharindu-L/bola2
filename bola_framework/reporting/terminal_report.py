"""Colorized terminal summary of confirmed BOLA findings, printed at the end
of a scan run alongside the JSON/Markdown report files.
"""

from __future__ import annotations

from bola_framework.models.finding import BolaClassification, Finding

try:
    from colorama import Fore, Style, init as _colorama_init

    _colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # colorama not installed -- degrade to plain text
    _COLOR = False

    class _NoColor:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _NoColor()
    Style = _NoColor()


def _severity_for(finding: Finding) -> str:
    if finding.classification == BolaClassification.CONFIRMED_BOLA:
        return "High"
    return "Low"


def _path_for(finding: Finding) -> str:
    description = finding.operation_description
    if " " in description:
        return description.split(" ", 1)[1]
    return description


def _operation_id_for(finding: Finding) -> str:
    method = finding.operation_description.split(" ", 1)[0] if " " in finding.operation_description else ""
    return f"{method}:{_path_for(finding)}"


def _similarity_for(finding: Finding) -> str:
    ratio = finding.evidence.shared_content_ratio
    if ratio is None:
        return "N/A"
    return f"{ratio * 100:.2f}%"


def print_findings_table(findings: list[Finding]) -> None:
    """Print a colorized table of confirmed BOLA vulnerabilities, matching the
    at-a-glance terminal summary format: Severity, API Type, Method,
    Path / Query, Similarity, Operation ID.
    """
    confirmed = [f for f in findings if f.classification == BolaClassification.CONFIRMED_BOLA]

    title = f"BOLA Findings — {len(confirmed)} vulnerability(s)"
    print()
    print(f"{Fore.RED}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print()

    if not confirmed:
        print(f"{Fore.YELLOW}No confirmed BOLA vulnerabilities in this run.{Style.RESET_ALL}")
        return

    headers = ["Severity", "API Type", "Method", "Path / Query", "Similarity", "Operation ID"]
    rows = []
    for finding in confirmed:
        method = finding.operation_description.split(" ", 1)[0] if " " in finding.operation_description else finding.api_type.upper()
        rows.append(
            [
                _severity_for(finding),
                finding.api_type.upper(),
                method,
                _path_for(finding),
                _similarity_for(finding),
                _operation_id_for(finding),
            ]
        )

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))
    ]

    def _format_row(cells: list[str], color: str = "") -> str:
        padded = [cell.ljust(widths[i]) for i, cell in enumerate(cells)]
        line = " | ".join(padded)
        return f"{color}{line}{Style.RESET_ALL}" if color else line

    print(_format_row(headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        severity_color = Fore.RED + Style.BRIGHT if row[0] == "High" else Fore.YELLOW
        print(_format_row(row, color=severity_color))
    print()


def print_report_paths(json_path: str, markdown_path: str) -> None:
    print(f"{Fore.GREEN}Report written to: {json_path}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Markdown report written to: {markdown_path}{Style.RESET_ALL}")
