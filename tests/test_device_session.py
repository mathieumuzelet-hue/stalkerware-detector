import pytest
from stalkerware_detector.device import adb, session


def test_parse_getprop_extracts_known_keys(fixture_text):
    info = session.parse_getprop(fixture_text("adb/getprop.txt"))
    assert info.android_release == "13"
    assert info.sdk_int == 33
    assert info.build_id == "TQ3A.230805.001"
    assert info.security_patch == "2026-04-05"
    assert info.manufacturer == "Google"
    assert info.model == "Pixel 7"


def test_redact_serial_keeps_last_four():
    assert session.redact_serial("ABCD1234EFGH") == "********EFGH"
    assert session.redact_serial("abc") == "abc"


def test_select_device_picks_only_one():
    devices = [adb.DeviceEntry(serial="X", state="device")]
    assert session.select_device(devices, requested=None, interactive=False) == "X"


def test_select_device_uses_requested_serial():
    devices = [
        adb.DeviceEntry(serial="A", state="device"),
        adb.DeviceEntry(serial="B", state="device"),
    ]
    assert session.select_device(devices, requested="B", interactive=False) == "B"


def test_select_device_requested_not_found_raises():
    devices = [adb.DeviceEntry(serial="A", state="device")]
    with pytest.raises(session.DeviceSelectionError):
        session.select_device(devices, requested="Z", interactive=False)


def test_select_device_no_devices_raises():
    with pytest.raises(session.NoDeviceError):
        session.select_device([], requested=None, interactive=False)


def test_select_device_multi_non_interactive_raises():
    devices = [
        adb.DeviceEntry(serial="A", state="device"),
        adb.DeviceEntry(serial="B", state="device"),
    ]
    with pytest.raises(session.AmbiguousDeviceError):
        session.select_device(devices, requested=None, interactive=False)


def test_select_device_unauthorized_raises():
    devices = [adb.DeviceEntry(serial="A", state="unauthorized")]
    with pytest.raises(session.DeviceUnauthorizedError):
        session.select_device(devices, requested=None, interactive=False)


def test_connect_returns_device_session(fixture_text, monkeypatch):
    monkeypatch.setattr(
        adb, "list_devices", lambda: [adb.DeviceEntry(serial="ABCD1234EFGH", state="device")]
    )
    monkeypatch.setattr(adb, "run_shell", lambda s, c, timeout=30: fixture_text("adb/getprop.txt"))
    sess = session.connect(requested_serial=None, interactive=False)
    assert sess.serial == "ABCD1234EFGH"
    assert sess.info.model == "Pixel 7"
