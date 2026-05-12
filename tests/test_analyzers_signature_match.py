from stalkerware_detector.analyzers import signature_match
from stalkerware_detector.models import FindingKind, Severity
from stalkerware_detector.signatures import loader


def _make_app(package: str, *, label: str | None = None):
    from stalkerware_detector.models import InstalledApp

    return InstalledApp(
        package=package,
        label=label,
        apk_path=f"/data/app/{package}/base.apk",
    )


def test_match_by_package_emits_critical_finding(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [_make_app("com.lsdroid.cerberus", label="Cerberus")]

    findings = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.kind is FindingKind.SIGNATURE_HIT
    assert f.target_package == "com.lsdroid.cerberus"
    assert f.evidence.get("matched_on") == "package"
    assert f.remediation.safety_first.strip()
    # French remediation: 3919 and 17 must be present in helplines
    phones = {h.phone for h in f.remediation.helplines if h.phone}
    assert "3919" in phones
    assert "17" in phones


def test_match_by_cert_when_package_unknown(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    # Package name unknown but cert hits Cerberus's certificate.
    apps = [_make_app("com.unknown.repackaged")]
    cert = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    certs_by_pkg = {"com.unknown.repackaged": cert}

    findings = signature_match.analyze(
        apps=apps, certs_by_pkg=certs_by_pkg, index=index
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.evidence.get("matched_on") == "cert"
    assert f.evidence.get("cert_sha256") == cert


def test_no_match_emits_no_findings(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [_make_app("com.google.android.apps.maps")]
    certs_by_pkg = {"com.google.android.apps.maps": "deadbeef" * 8}

    findings = signature_match.analyze(
        apps=apps, certs_by_pkg=certs_by_pkg, index=index
    )

    assert findings == []


def test_finding_id_is_stable(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [_make_app("com.lsdroid.cerberus")]

    first = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    second = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)

    assert first[0].id == second[0].id
    # Same input across calls must produce the same SHA-1 ID derived from
    # f"signature_hit|{package}|{matched_on}|{ioc.name}".
    import hashlib

    expected = hashlib.sha1(
        b"signature_hit|com.lsdroid.cerberus|package|cerberus"
    ).hexdigest()
    assert first[0].id == expected
