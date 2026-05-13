from pathlib import Path

from stalkerware_detector import __version__
from stalkerware_detector.cli import app
from stalkerware_detector.device import adb, session
from stalkerware_detector.signatures import fetcher, loader
from stalkerware_detector.signatures.loader import IOCIndex, SampleIOC
from typer.testing import CliRunner

runner = CliRunner()


def _nonempty_index() -> IOCIndex:
    ioc = SampleIOC(name="Demo", type="stalkerware", package="com.demo")
    idx = IOCIndex()
    idx.by_package[ioc.package] = ioc
    return idx


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
    monkeypatch.setattr(fetcher, "default_cache_dir", lambda: Path("/tmp/no-such"))
    monkeypatch.setattr(loader, "load_index", lambda root: _nonempty_index())
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Pixel 7" in result.stdout
    assert "EFGH" in result.stdout  # redacted serial keeps last 4
    assert "signatures" in result.stdout.lower()


def test_doctor_warns_on_empty_signature_cache(monkeypatch, fixture_text):
    monkeypatch.setattr(adb, "adb_available", lambda: "/usr/bin/adb")
    monkeypatch.setattr(adb, "adb_version", lambda: "Android Debug Bridge version 1.0.41\n")
    monkeypatch.setattr(adb, "list_devices", lambda: [adb.DeviceEntry("ABCD1234EFGH", "device")])
    monkeypatch.setattr(adb, "run_shell", lambda s, c, timeout=30: fixture_text("adb/getprop.txt"))
    monkeypatch.setattr(fetcher, "default_cache_dir", lambda: Path("/tmp/no-such"))
    monkeypatch.setattr(loader, "load_index", lambda root: IOCIndex())
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 22
    assert "update-sigs" in result.stdout


def test_scan_no_device_exits_11(monkeypatch):
    """run_scan raising NoDeviceError must map to documented exit 11."""
    from stalkerware_detector import scan as scan_mod

    def _boom(**kwargs):
        raise session.NoDeviceError("no device attached")

    monkeypatch.setattr(scan_mod, "run_scan", _boom)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 11
    assert "device" in result.stdout.lower() or "aucun" in result.stdout.lower()
