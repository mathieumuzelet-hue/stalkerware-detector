"""Active accessibility service packages."""
from __future__ import annotations

from ..device import adb


def parse_enabled(output: str) -> list[str]:
    raw = output.strip()
    if not raw or raw.lower() == "null":
        return []
    pkgs: list[str] = []
    seen: set[str] = set()
    for entry in raw.split(":"):
        entry = entry.strip()
        if not entry or "/" not in entry:
            continue
        pkg = entry.split("/", 1)[0]
        if pkg and pkg not in seen:
            seen.add(pkg)
            pkgs.append(pkg)
    return pkgs


def collect(serial: str) -> list[str]:
    try:
        out = adb.run_shell(serial, "settings get secure enabled_accessibility_services")
    except adb.AdbError:
        return []
    return parse_enabled(out)
