from stalkerware_detector import __version__
from stalkerware_detector.cli import app
from stalkerware_detector.device import adb
from typer.testing import CliRunner

runner = CliRunner()


def test_version_command_prints_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_doctor_reports_adb_missing(monkeypatch):
    monkeypatch.setattr(adb, "adb_available", lambda: None)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 10
    assert "adb" in result.stdout.lower()


def test_doctor_reports_no_device(monkeypatch):
    monkeypatch.setattr(adb, "adb_available", lambda: "/usr/bin/adb")
    monkeypatch.setattr(adb, "adb_version", lambda: "Android Debug Bridge version 1.0.41\n")
    monkeypatch.setattr(adb, "list_devices", lambda: [])
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 11
    assert "no device" in result.stdout.lower() or "aucun" in result.stdout.lower()


def test_doctor_happy_path(monkeypatch, fixture_text):
    monkeypatch.setattr(adb, "adb_available", lambda: "/usr/bin/adb")
    monkeypatch.setattr(adb, "adb_version", lambda: "Android Debug Bridge version 1.0.41\n")
    monkeypatch.setattr(adb, "list_devices", lambda: [adb.DeviceEntry("ABCD1234EFGH", "device")])
    monkeypatch.setattr(adb, "run_shell", lambda s, c, timeout=30: fixture_text("adb/getprop.txt"))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Pixel 7" in result.stdout
    assert "EFGH" in result.stdout  # redacted serial keeps last 4
