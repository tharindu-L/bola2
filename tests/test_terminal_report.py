from bola_framework.models.finding import BolaClassification, ConfidenceLevel, Evidence, Finding
from bola_framework.reporting.terminal_report import (
    _operation_id_for,
    _path_for,
    _severity_for,
    _similarity_for,
    print_findings_table,
)


def _confirmed_finding():
    return Finding(
        finding_id="BOLA-0001",
        classification=BolaClassification.CONFIRMED_BOLA,
        confidence=ConfidenceLevel.CONFIRMED,
        operation_id="auto.GET./rest/basket/{param1}",
        api_type="rest",
        operation_description="GET /rest/basket/{param1}",
        evidence=Evidence(shared_content_ratio=1.0),
    )


def test_severity_and_fields_for_confirmed_finding():
    finding = _confirmed_finding()
    assert _severity_for(finding) == "High"
    assert _path_for(finding) == "/rest/basket/{param1}"
    assert _operation_id_for(finding) == "GET:/rest/basket/{param1}"
    assert _similarity_for(finding) == "100.00%"


def test_print_findings_table_does_not_raise_with_no_findings(capsys):
    print_findings_table([])
    captured = capsys.readouterr()
    assert "0 vulnerability(s)" in captured.out


def test_print_findings_table_lists_confirmed_only(capsys):
    findings = [
        _confirmed_finding(),
        Finding(
            finding_id="BOLA-0002",
            classification=BolaClassification.PUBLIC_RESOURCE,
            confidence=ConfidenceLevel.SUSPECTED,
            operation_id="auto.GET./{param1}",
            api_type="rest",
            operation_description="GET /application-version",
            evidence=Evidence(shared_content_ratio=1.0),
        ),
    ]
    print_findings_table(findings)
    captured = capsys.readouterr()
    assert "1 vulnerability(s)" in captured.out
    assert "/rest/basket/{param1}" in captured.out
    assert "/application-version" not in captured.out
