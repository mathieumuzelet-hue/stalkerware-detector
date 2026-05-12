from io import StringIO

from rich.console import Console
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
from stalkerware_detector.reporters import console as console_reporter


def _report(findings):
    return ScanReport(
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH",
            manufacturer="Google",
            model="Pixel 7",
            android_release="13",
            sdk_int=33,
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=findings,
        safety_warning="warn",
    )


def _make_critical(pkg: str) -> Finding:
    return Finding(
        id=f"id-{pkg}",
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package=pkg,
        summary=f"Stalkerware connu détecté : {pkg}",
        details="...",
        evidence={"matched_on": "package"},
        remediation=RemediationAdvice(
            risk_summary="risk",
            safety_first="be careful",
            steps=["step1"],
            helplines=[Helpline(name="3919", phone="3919")],
        ),
    )


def test_render_shows_device_info_and_findings():
    buf = StringIO()
    rich_console = Console(file=buf, force_terminal=False, width=120)
    report = _report([_make_critical("com.spy.one")])
    console_reporter.render(report, rich_console=rich_console)
    out = buf.getvalue()
    assert "Pixel 7" in out
    assert "****EFGH" in out
    assert "com.spy.one" in out
    assert "CRITICAL" in out.upper()


def test_render_no_findings_prints_clean_message():
    buf = StringIO()
    rich_console = Console(file=buf, force_terminal=False, width=120)
    report = _report([])
    console_reporter.render(report, rich_console=rich_console)
    out = buf.getvalue()
    assert "aucun" in out.lower() or "no finding" in out.lower()


def test_compute_exit_code_matches_spec():
    assert console_reporter.compute_exit_code(_report([])) == 0
    low = _make_critical("com.x").model_copy(update={"severity": Severity.LOW})
    low_advice = low.remediation.model_copy(update={"safety_first": ""})
    low = low.model_copy(update={"remediation": low_advice})
    assert console_reporter.compute_exit_code(_report([low])) == 1
    med = low.model_copy(update={"severity": Severity.MEDIUM})
    assert console_reporter.compute_exit_code(_report([med])) == 1
    high = _make_critical("com.x").model_copy(update={"severity": Severity.HIGH})
    assert console_reporter.compute_exit_code(_report([high])) == 2
    crit = _make_critical("com.x")
    assert console_reporter.compute_exit_code(_report([crit])) == 3
