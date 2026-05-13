from stalkerware_detector.collectors import permissions


def test_parse_runtime_permissions_grants(fixture_text):
    perms = permissions.parse_permissions(fixture_text("dumpsys/package_suspicious.txt"))
    names = {p.name for p in perms if p.granted}
    assert "android.permission.RECORD_AUDIO" in names
    assert "android.permission.ACCESS_FINE_LOCATION" in names
    assert "android.permission.READ_SMS" in names
    assert "android.permission.READ_CONTACTS" in names


def test_parse_permissions_legit_app_has_no_sensitive(fixture_text):
    perms = permissions.parse_permissions(fixture_text("dumpsys/package_legit.txt"))
    granted = {p.name for p in perms if p.granted}
    assert granted == {"android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"}


def test_collect_returns_permissions_per_package(monkeypatch, fixture_text):
    from stalkerware_detector.device import adb
    from stalkerware_detector.models import InstalledApp

    def fake_run(serial, cmd, timeout=30):
        pkg = cmd.split()[-1]
        if pkg == "com.example.spy":
            return fixture_text("dumpsys/package_suspicious.txt")
        return fixture_text("dumpsys/package_legit.txt")

    monkeypatch.setattr(adb, "run_shell", fake_run)
    apps = [
        InstalledApp(package="com.example.spy", apk_path="/data/app/x/base.apk"),
        InstalledApp(
            package="com.google.android.apps.maps",
            apk_path="/system/app/Maps.apk",
            system=True,
        ),
    ]
    out = permissions.collect("ABCD", apps)
    assert "com.example.spy" in out
    assert any(p.name == "android.permission.RECORD_AUDIO" for p in out["com.example.spy"])
