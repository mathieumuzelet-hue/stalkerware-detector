from stalkerware_detector import scan
from stalkerware_detector.device import session
from stalkerware_detector.models import FindingKind, InstalledApp, Severity
from stalkerware_detector.signatures.fetcher import IndexMeta


def _make_session():
    info = session.DeviceInfo(
        manufacturer="Google", model="Pixel 7",
        android_release="13", sdk_int=33,
        build_id="X", security_patch="2026-04",
    )
    return session.DeviceSession(serial="ABCD1234EFGH", info=info)


def test_run_scan_returns_report_with_signature_finding(monkeypatch, fixtures_dir):
    sess = _make_session()
    apps = [
        InstalledApp(package="com.lsdroid.cerberus", apk_path="/data/app/x/base.apk"),
        InstalledApp(package="com.android.chrome", apk_path="/data/app/y/base.apk"),
    ]

    monkeypatch.setattr(scan.session, "connect", lambda **kw: sess)
    monkeypatch.setattr(scan.packages, "collect", lambda serial: apps)
    monkeypatch.setattr(scan, "_collect_certs", lambda serial, apps: {})

    fake_fetcher_target = fixtures_dir / "echap_mini"
    monkeypatch.setattr(
        scan.fetcher, "ensure_fresh",
        lambda target, allow_network, force=False: IndexMeta(fetched_at=1.0, commit="abc"),
    )
    monkeypatch.setattr(scan.fetcher, "default_cache_dir", lambda: fake_fetcher_target)

    report = scan.run_scan(serial=None, allow_network=True, interactive=False)
    sigs = [f for f in report.findings if f.kind is FindingKind.SIGNATURE_HIT]
    assert len(sigs) == 1
    assert sigs[0].target_package == "com.lsdroid.cerberus"
    assert sigs[0].severity is Severity.CRITICAL
    assert report.device.serial_redacted.endswith("EFGH")
