from stalkerware_detector.analyzers import permission_risk
from stalkerware_detector.models import (
    FindingKind,
    GrantedPermission,
    InstalledApp,
    Severity,
)


def _perms(*names: str) -> list[GrantedPermission]:
    return [GrantedPermission(name=f"android.permission.{n}", granted=True) for n in names]


def _app(pkg: str, *, system=False, installer=None) -> InstalledApp:
    return InstalledApp(
        package=pkg,
        apk_path=("/system/" if system else "/data/") + "app/x/base.apk",
        installer_package=installer,
        system=system,
    )


def test_system_apps_are_ignored():
    apps = [_app("com.android.systemui", system=True)]
    perms = {"com.android.systemui": _perms("RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS")}
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    assert findings == []


def test_high_score_with_accessibility_is_HIGH():
    apps = [_app("com.example.spy", installer=None)]
    perms = {
        "com.example.spy": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_SMS", "READ_CONTACTS",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=["com.example.spy"], allowlist=set(),  # noqa: E501
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.HIGH


def test_high_score_without_privilege_is_MEDIUM():
    apps = [_app("com.example.spy", installer="com.android.vending")]
    perms = {
        "com.example.spy": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_SMS", "READ_CONTACTS",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.MEDIUM


def test_sideloaded_with_score_3_is_MEDIUM():
    apps = [_app("com.example.spy", installer=None)]
    perms = {"com.example.spy": _perms("RECORD_AUDIO", "READ_SMS", "READ_CONTACTS")}
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.MEDIUM


def test_allowlist_suppresses_permission_profile():
    apps = [_app("com.whatsapp", installer="com.android.vending")]
    perms = {
        "com.whatsapp": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS",
            "READ_CONTACTS", "READ_CALL_LOG",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist={"com.whatsapp"},  # noqa: E501
    )
    assert all(f.kind is not FindingKind.PERMISSION_PROFILE for f in findings)


def test_device_admin_emits_HIGH_side_channel_finding():
    apps = [_app("com.example.spy", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=["com.example.spy"], accessibility=[], allowlist=set(),  # noqa: E501
    )
    da = [f for f in findings if f.kind is FindingKind.DEVICE_ADMIN]
    assert len(da) == 1
    assert da[0].severity is Severity.HIGH


def test_accessibility_emits_HIGH_side_channel_finding():
    apps = [_app("com.example.spy", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=["com.example.spy"], allowlist=set(),  # noqa: E501
    )
    acc = [f for f in findings if f.kind is FindingKind.ACCESSIBILITY_SVC]
    assert len(acc) == 1
    assert acc[0].severity is Severity.HIGH


def test_sideloaded_emits_LOW_side_channel_finding():
    apps = [_app("com.example.app", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=[], allowlist=set(),
    )
    side = [f for f in findings if f.kind is FindingKind.SIDELOADED_APP]
    assert len(side) == 1
    assert side[0].severity is Severity.LOW


def test_known_store_does_not_emit_sideloaded_finding():
    apps = [_app("com.example.app", installer="com.android.vending")]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=[], allowlist=set(),
    )
    assert all(f.kind is not FindingKind.SIDELOADED_APP for f in findings)


def test_sideloaded_finding_emitted_for_unknown_installer():
    """An installer that's neither None nor a known store is still sideloaded."""
    apps = [_app("com.example.spy", installer="com.example.unknown")]
    perms = {"com.example.spy": _perms("RECORD_AUDIO", "READ_SMS", "READ_CONTACTS")}
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    side = [f for f in findings if f.kind is FindingKind.SIDELOADED_APP]
    assert len(side) == 1
    # Score should be doubled because sideloaded=True (3 sensitive perms -> score 6)
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile
    assert profile[0].evidence["sideloaded"] is True
    assert profile[0].evidence["adjusted_score"] == 6
    assert profile[0].evidence["raw_score"] == 3
