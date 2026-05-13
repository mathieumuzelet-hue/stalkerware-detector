"""Active device-admin receivers from `dumpsys device_policy`."""
from __future__ import annotations

import re

from ..device import adb

# Lines look like:    com.example.spy/.AdminReceiver:
_ADMIN_LINE = re.compile(r"^\s+(?P<pkg>[A-Za-z0-9_.]+)/[A-Za-z0-9_.$]+:\s*$")


def parse_active(dump: str) -> list[str]:
    pkgs: list[str] = []
    seen: set[str] = set()
    inside = False
    for line in dump.splitlines():
        if "Enabled Device Admins" in line:
            inside = True
            continue
        if inside:
            if line.strip() == "" or not line.startswith(" "):
                if line.strip() == "":
                    continue
                inside = False
                continue
            m = _ADMIN_LINE.match(line)
            if m and m.group("pkg") not in seen:
                seen.add(m.group("pkg"))
                pkgs.append(m.group("pkg"))
    return pkgs


def collect(serial: str) -> list[str]:
    try:
        dump = adb.run_shell(serial, "dumpsys device_policy")
    except adb.AdbError:
        return []
    return parse_active(dump)
