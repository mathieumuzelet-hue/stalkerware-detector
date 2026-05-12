import pytest
from pydantic import ValidationError
from stalkerware_detector import models


def test_finding_critical_requires_safety_first():
    with pytest.raises(ValidationError):
        models.Finding(
            id="x",
            severity=models.Severity.CRITICAL,
            kind=models.FindingKind.SIGNATURE_HIT,
            target_package="com.example.spy",
            summary="match",
            details="...",
            evidence={},
            remediation=models.RemediationAdvice(
                risk_summary="...", safety_first="", steps=[], helplines=[]
            ),
        )


def test_finding_low_allows_empty_safety_first():
    f = models.Finding(
        id="x",
        severity=models.Severity.LOW,
        kind=models.FindingKind.SIDELOADED_APP,
        target_package="com.example",
        summary="sideloaded",
        details="...",
        evidence={},
        remediation=models.RemediationAdvice(
            risk_summary="...", safety_first="", steps=[], helplines=[]
        ),
    )
    assert f.severity is models.Severity.LOW


def test_scan_report_summary_counts():
    rep = models.ScanReport(
        schema_version="1.0",
        tool_version="0.1.0",
        device=models.DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33, build_id="X", security_patch="2026-04",
        ),
        signature_index=models.SignatureIndexMeta(commit="abc", fetched_at=1.0),
        findings=[
            _make_finding(models.Severity.CRITICAL),
            _make_finding(models.Severity.HIGH),
            _make_finding(models.Severity.HIGH),
        ],
        safety_warning="...",
    )
    assert rep.summary[models.Severity.CRITICAL] == 1
    assert rep.summary[models.Severity.HIGH] == 2
    assert rep.summary.get(models.Severity.LOW, 0) == 0


def _make_finding(severity):
    return models.Finding(
        id=f"f-{severity.value}",
        severity=severity,
        kind=models.FindingKind.SIGNATURE_HIT,
        target_package="com.spy",
        summary="...",
        details="...",
        evidence={},
        remediation=models.RemediationAdvice(
            risk_summary="risk",
            safety_first=(
                "warn"
                if severity in {models.Severity.CRITICAL, models.Severity.HIGH}
                else ""
            ),
            steps=[],
            helplines=[],
        ),
    )
