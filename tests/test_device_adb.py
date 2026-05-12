from unittest.mock import MagicMock, patch

import pytest
from stalkerware_detector.device import adb


def test_adb_available_returns_path_when_found(monkeypatch):
    monkeypatch.setattr(adb.shutil, "which", lambda _: "/usr/bin/adb")
    assert adb.adb_available() == "/usr/bin/adb"


def test_adb_available_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(adb.shutil, "which", lambda _: None)
    assert adb.adb_available() is None


def test_parse_devices_empty(fixture_text):
    assert adb.parse_devices(fixture_text("adb/devices_empty.txt")) == []


def test_parse_devices_one(fixture_text):
    devices = adb.parse_devices(fixture_text("adb/devices_one.txt"))
    assert devices == [adb.DeviceEntry(serial="ABCD1234EFGH", state="device")]


def test_parse_devices_multi(fixture_text):
    devices = adb.parse_devices(fixture_text("adb/devices_multi.txt"))
    assert [d.serial for d in devices] == ["ABCD1234EFGH", "WXYZ5678PQRS"]
    assert all(d.state == "device" for d in devices)


def test_parse_devices_unauthorized(fixture_text):
    devices = adb.parse_devices(fixture_text("adb/devices_unauthorized.txt"))
    assert devices[0].state == "unauthorized"


def test_parse_devices_no_permissions_state(fixture_text):
    devices = adb.parse_devices(fixture_text("adb/devices_no_permissions.txt"))
    assert len(devices) == 1
    assert devices[0].state.startswith("no permissions")


def test_run_shell_calls_subprocess_correctly():
    fake_result = MagicMock(stdout="hello", stderr="", returncode=0)
    with patch("stalkerware_detector.device.adb.subprocess.run", return_value=fake_result) as run:
        out = adb.run_shell("ABCD1234", "echo hi", timeout=5)
    assert out == "hello"
    run.assert_called_once()
    args = run.call_args.args[0]
    assert args[:5] == ["adb", "-s", "ABCD1234", "shell", "echo hi"]


def test_run_shell_raises_on_nonzero_exit():
    fake_result = MagicMock(stdout="", stderr="boom", returncode=1)
    with (
        patch("stalkerware_detector.device.adb.subprocess.run", return_value=fake_result),
        pytest.raises(adb.AdbError) as exc,
    ):
        adb.run_shell("ABCD1234", "false", timeout=5)
    assert "boom" in str(exc.value)
