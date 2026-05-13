"""Collect granted runtime + install permissions per package from dumpsys."""
from __future__ import annotations

import re

from ..device import adb
from ..models import GrantedPermission, InstalledApp

_PERM_LINE = re.compile(
    r"^\s+(?P<name>android\.permission\.[A-Z0-9_]+):\s+granted=(?P<g>true|false)"
)


def parse_permissions(dump: str) -> list[GrantedPermission]:
    out: list[GrantedPermission] = []
    seen: set[str] = set()
    for line in dump.splitlines():
        m = _PERM_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        if name in seen:
            continue
        seen.add(name)
        out.append(GrantedPermission(name=name, granted=m.group("g") == "true"))
    return out


def collect(serial: str, apps: list[InstalledApp]) -> dict[str, list[GrantedPermission]]:
    """Return granted permissions per package. Skips errors silently per app."""
    result: dict[str, list[GrantedPermission]] = {}
    for app in apps:
        try:
            dump = adb.run_shell(serial, f"dumpsys package {app.package}")
        except adb.AdbError:
            continue
        result[app.package] = parse_permissions(dump)
    return result
