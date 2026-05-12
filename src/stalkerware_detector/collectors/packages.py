"""Collect the list of installed packages, with metadata."""
from __future__ import annotations

import re
from datetime import datetime

from ..device import adb
from ..models import InstalledApp

# `pm list packages -f -U -i -u` lines look like:
#   package:/path/base.apk=com.pkg.name  installer=com.android.vending  uid:10123
# Note: APK paths can contain "==" (data dir suffixes), so we anchor `apk_path` on
# ".apk" instead of "[^=]+" — the latter is fooled by real `/data/app/~~Ab==/...` paths.
_PM_LIST_LINE = re.compile(
    r"^package:(?P<apk_path>.+?\.apk)=(?P<package>[A-Za-z0-9_.]+)"
    r"(?:\s+installer=(?P<installer>\S+))?"
    r"(?:\s+uid:\S+)?\s*$"
)

_SYSTEM_PREFIXES = ("/system/", "/system_ext/", "/product/", "/vendor/", "/apex/")


def collect(serial: str) -> list[InstalledApp]:
    """Return all installed apps with enriched metadata."""
    pm_out = adb.run_shell(serial, "pm list packages -f -U -i -u")
    apps = parse_pm_list(pm_out)
    enriched: list[InstalledApp] = []
    for app in apps:
        try:
            dump = adb.run_shell(serial, f"dumpsys package {app.package}")
        except adb.AdbError:
            enriched.append(app)
            continue
        enriched.append(enrich_with_dumpsys(app, dump))
    return enriched


def parse_pm_list(output: str) -> list[InstalledApp]:
    apps: list[InstalledApp] = []
    for line in output.splitlines():
        m = _PM_LIST_LINE.match(line.strip())
        if not m:
            continue
        apk_path = m.group("apk_path")
        installer = m.group("installer")
        if installer in (None, "null"):
            installer = None
        apps.append(
            InstalledApp(
                package=m.group("package"),
                apk_path=apk_path,
                installer_package=installer,
                system=is_system_path(apk_path),
            )
        )
    return apps


def is_system_path(apk_path: str) -> bool:
    return apk_path.startswith(_SYSTEM_PREFIXES)


_VERSION_NAME = re.compile(r"^\s*versionName=(?P<v>\S+)\s*$", re.MULTILINE)
_VERSION_CODE = re.compile(r"^\s*versionCode=(?P<v>\d+)", re.MULTILINE)
_FIRST_INSTALL = re.compile(r"^\s*firstInstallTime=(?P<v>.+)$", re.MULTILINE)
_LAST_UPDATE = re.compile(r"^\s*lastUpdateTime=(?P<v>.+)$", re.MULTILINE)


def enrich_with_dumpsys(app: InstalledApp, dump: str) -> InstalledApp:
    """Return a copy of `app` enriched with versions and install dates from dumpsys."""
    def _date(s: str | None) -> datetime | None:
        if not s:
            return None
        s = s.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    vn = _VERSION_NAME.search(dump)
    vc = _VERSION_CODE.search(dump)
    fi = _FIRST_INSTALL.search(dump)
    lu = _LAST_UPDATE.search(dump)

    return app.model_copy(update={
        "version_name": vn.group("v") if vn else None,
        "version_code": int(vc.group("v")) if vc else None,
        "first_install_time": _date(fi.group("v")) if fi else None,
        "last_update_time": _date(lu.group("v")) if lu else None,
    })
