from datetime import datetime
from pathlib import Path

from stalkerware_detector.models import (
    DeviceInfo,
    Finding,
    FindingKind,
    Helpline,
    RemediationAdvice,
    ScanReport,
    Severity,
    SignatureIndexMeta,
)
from stalkerware_detector.reporters import html_report


def _critical_finding():
    return Finding(
        id="f1",
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package="com.lsdroid.cerberus",
        summary="Stalkerware connu : cerberus",
        details="détails.",
        evidence={},
        remediation=RemediationAdvice(
            risk_summary="risk",
            safety_first="be careful",
            steps=["s1", "s2"],
            helplines=[Helpline(name="3919", phone="3919")],
        ),
    )


def _report(findings):
    return ScanReport(
        generated_at=datetime(2026, 5, 13, 12, 0, 0),
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33, security_patch="2026-04",
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=findings,
        safety_warning="warn",
    )


def test_render_html_contains_critical_finding_and_safety_banner():
    html = html_report.render_html(_report([_critical_finding()]))
    assert "Stalkerware connu" in html
    assert "com.lsdroid.cerberus" in html
    assert "be careful" in html
    assert 'class="safety"' in html


def test_render_html_no_safety_banner_when_no_severe_findings():
    html = html_report.render_html(_report([]))
    assert "Aucun finding" in html
    # Safety banner should NOT appear at top level if no high/critical
    assert html.count('class="safety"') == 0


def test_render_html_has_no_external_resources():
    html = html_report.render_html(_report([_critical_finding()]))
    assert "<script" not in html.lower()
    assert "http://" not in html  # but allow https for safety links
    # Allowed https URLs only inside helpline section
    for line in html.splitlines():
        if "src=" in line:
            assert False, f"External resource referenced: {line}"  # noqa: B011


def test_write_creates_file(tmp_path: Path):
    out = tmp_path / "report.html"
    html_report.write(_report([_critical_finding()]), out)
    assert out.exists()
    assert "Stalkerware connu" in out.read_text(encoding="utf-8")
