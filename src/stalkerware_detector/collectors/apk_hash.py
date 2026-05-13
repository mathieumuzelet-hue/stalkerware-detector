"""Compute SHA-256 of APKs by pulling them via adb (optional, off by default)."""
from __future__ import annotations

import contextlib
import hashlib
import logging
from pathlib import Path

from ..device import adb
from ..models import InstalledApp

log = logging.getLogger(__name__)


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(
    serial: str,
    apps: list[InstalledApp],
    *,
    tmp_dir: Path,
    timeout_per_apk: int = 30,
) -> dict[str, str]:
    """Return {package: sha256} for non-system, sideloaded apps."""
    out: dict[str, str] = {}
    tmp_dir.mkdir(parents=True, exist_ok=True)
    for app in apps:
        if app.system:
            continue
        if app.installer_package is not None:
            # Only hash sideloaded apps; store-installed apps don't need it.
            continue
        local = tmp_dir / f"{app.package}.apk"
        try:
            adb.pull(serial, app.apk_path, str(local), timeout=timeout_per_apk)
        except adb.AdbError as e:
            log.info("apk pull failed for %s: %s", app.package, e)
            continue
        try:
            out[app.package] = sha256_of_file(local)
        finally:
            with contextlib.suppress(FileNotFoundError):
                local.unlink()
    return out
