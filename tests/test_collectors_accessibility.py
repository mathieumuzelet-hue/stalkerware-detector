from stalkerware_detector.collectors import accessibility


def test_parse_extracts_packages(fixture_text):
    pkgs = accessibility.parse_enabled(fixture_text("adb/enabled_accessibility.txt"))
    assert set(pkgs) == {"com.example.spy", "com.android.talkback"}


def test_parse_empty_string():
    assert accessibility.parse_enabled("\n") == []
    assert accessibility.parse_enabled("null\n") == []
