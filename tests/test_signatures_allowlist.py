from importlib.resources import files

from stalkerware_detector.signatures import loader


def test_load_allowlist_returns_set_of_packages():
    allow = loader.load_allowlist()
    assert "com.whatsapp" in allow
    assert "org.thoughtcrime.securesms" in allow
    assert "com.google.android.apps.maps" in allow
    assert len(allow) >= 25


def test_allowlist_yaml_is_packaged():
    res = files("stalkerware_detector.signatures").joinpath("legitimate_apps.yaml")
    assert res.is_file()
