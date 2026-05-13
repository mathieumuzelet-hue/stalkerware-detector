import json
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
from stalkerware_detector.reporters import json_report


def _sample_report():
    return ScanReport(
        generated_at=datetime(2026, 5, 13, 12, 0, 0),
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33,
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=[
            Finding(
                id="f1",
                severity=Severity.CRITICAL,
                kind=FindingKind.SIGNATURE_HIT,
                target_package="com.lsdroid.cerberus",
                summary="Stalkerware connu : cerberus",
                details="...",
                evidence={"matched_on": "package"},
                remediation=RemediationAdvice(
                    risk_summary="risk",
                    safety_first="warn",
                    steps=["s1"],
                    helplines=[Helpline(name="3919", phone="3919")],
                ),
            ),
        ],
        safety_warning="warn",
    )


def test_write_creates_valid_json(tmp_path: Path):
    out = tmp_path / "scan.json"
    json_report.write(_sample_report(), out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["device"]["model"] == "Pixel 7"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["evidence"]["matched_on"] == "package"
    assert payload["summary"]["critical"] == 1


def test_to_dict_is_stable_snapshot(snapshot):
    payload = json_report.to_dict(_sample_report())
    assert payload == snapshot
