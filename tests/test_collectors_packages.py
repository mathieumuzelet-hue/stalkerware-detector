from stalkerware_detector.collectors import packages
from stalkerware_detector.device import adb


def test_parse_pm_list_extracts_apk_path_package_installer(fixture_text):
    apps = packages.parse_pm_list(fixture_text("adb/pm_list_packages.txt"))
    by_pkg = {a.package: a for a in apps}

    maps = by_pkg["com.google.android.apps.maps"]
    assert maps.apk_path == "/system/app/Maps/Maps.apk"
    assert maps.installer_package == "com.android.vending"

    spy = by_pkg["com.example.spy"]
    assert spy.apk_path.endswith("/base.apk")
    assert spy.installer_package is None


def test_classify_system_paths():
    assert packages.is_system_path("/system/app/Maps/Maps.apk") is True
    assert packages.is_system_path("/system/priv-app/SystemUI/SystemUI.apk") is True
    assert packages.is_system_path("/data/app/~~Ab/com.example-1==/base.apk") is False


def test_enrich_with_dumpsys_fills_versions_and_dates(fixture_text):
    app = packages.InstalledApp(
        package="com.example.spy",
        apk_path="/data/app/~~AbCdEf==/com.example.spy-1==/base.apk",
        installer_package=None,
    )
    enriched = packages.enrich_with_dumpsys(app, fixture_text("dumpsys/package_suspicious.txt"))
    assert enriched.version_name == "2.5.1"
    assert enriched.version_code == 251
    assert enriched.first_install_time is not None
    assert enriched.last_update_time is not None


def test_collect_uses_adb_run_shell(monkeypatch, fixture_text):
    calls = []

    def fake_run(serial, cmd, timeout=30):
        calls.append(cmd)
        if cmd.startswith("pm list packages"):
            return fixture_text("adb/pm_list_packages.txt")
        if cmd.startswith("dumpsys package "):
            pkg = cmd.split()[-1]
            if pkg == "com.example.spy":
                return fixture_text("dumpsys/package_suspicious.txt")
            return fixture_text("dumpsys/package_legit.txt")
        return ""

    monkeypatch.setattr(adb, "run_shell", fake_run)
    apps = packages.collect("ABCD")
    assert {a.package for a in apps} == {
        "com.google.android.apps.maps",
        "com.example.spy",
        "com.android.systemui",
        "com.android.chrome",
    }
    by_pkg = {a.package: a for a in apps}
    assert by_pkg["com.example.spy"].version_name == "2.5.1"
    assert by_pkg["com.android.systemui"].system is True
