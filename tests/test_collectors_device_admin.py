from stalkerware_detector.collectors import device_admin


def test_parse_extracts_package_names(fixture_text):
    pkgs = device_admin.parse_active(fixture_text("dumpsys/device_policy.txt"))
    assert set(pkgs) == {"com.example.spy", "com.google.android.apps.work.clouddpc"}


def test_parse_empty_when_no_admins():
    dump = "Current Device Policy Manager state:\n  Owner: <none>\n"
    assert device_admin.parse_active(dump) == []
