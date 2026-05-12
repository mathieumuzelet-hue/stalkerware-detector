from stalkerware_detector.analyzers import signature_match
from stalkerware_detector.models import FindingKind, InstalledApp, Severity
from stalkerware_detector.signatures import loader


def test_match_by_package_emits_critical_finding(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.lsdroid.cerberus",
            apk_path="/data/app/x/base.apk",
            installer_package=None,
        )
    ]
    findings = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.kind is FindingKind.SIGNATURE_HIT
    assert f.evidence["matched_on"] == "package"
    assert f.evidence["ioc_name"] == "cerberus"
    assert f.remediation.safety_first  # non-empty


def test_match_by_cert_when_package_unknown(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.renamed.example",
            apk_path="/data/app/x/base.apk",
            installer_package=None,
        )
    ]
    certs = {
        "com.renamed.example": [
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        ]
    }
    findings = signature_match.analyze(apps=apps, certs_by_pkg=certs, index=index)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["matched_on"] == "cert"


def test_no_match_emits_no_findings(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.android.chrome",
            apk_path="/data/app/x/base.apk",
            installer_package="com.android.vending",
        )
    ]
    findings = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert findings == []


def test_finding_id_is_stable(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.lsdroid.cerberus",
            apk_path="/data/app/x/base.apk",
        )
    ]
    a = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    b = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert a[0].id == b[0].id
