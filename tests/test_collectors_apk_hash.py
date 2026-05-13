import hashlib
from pathlib import Path
from unittest.mock import patch

from stalkerware_detector.collectors import apk_hash
from stalkerware_detector.models import InstalledApp


def test_sha256_of_file(tmp_path: Path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"hello")
    assert apk_hash.sha256_of_file(f) == hashlib.sha256(b"hello").hexdigest()


def test_collect_returns_hash_per_non_system_sideloaded_app(tmp_path: Path):
    apps = [
        InstalledApp(
            package="com.android.systemui",
            apk_path="/system/app/SystemUI.apk",
            system=True,
        ),
        InstalledApp(package="com.example.spy", apk_path="/data/app/x/base.apk",
                     installer_package=None, system=False),
    ]

    def fake_pull(serial, remote, local, timeout=30):
        Path(local).write_bytes(b"spy-apk")
        return ""

    with patch("stalkerware_detector.collectors.apk_hash.adb.pull", side_effect=fake_pull):
        hashes = apk_hash.collect("ABCD", apps, tmp_dir=tmp_path)
    assert "com.android.systemui" not in hashes
    assert hashes["com.example.spy"] == hashlib.sha256(b"spy-apk").hexdigest()


def test_collect_skips_silently_on_pull_error(tmp_path: Path):
    from stalkerware_detector.device.adb import AdbError
    apps = [
        InstalledApp(package="com.example.spy", apk_path="/data/app/x/base.apk",
                     installer_package=None, system=False),
    ]

    def boom(*a, **kw):
        raise AdbError("permission denied")

    with patch("stalkerware_detector.collectors.apk_hash.adb.pull", side_effect=boom):
        hashes = apk_hash.collect("ABCD", apps, tmp_dir=tmp_path)
    assert hashes == {}
