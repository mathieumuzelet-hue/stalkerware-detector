"""Subprocess boundary for the Android Debug Bridge.

This module is the ONLY place in the codebase that calls `subprocess.run(["adb", ...])`.
All higher-level code talks to ADB through `run_shell()` / `pull()` and receives plain
text it can parse. This keeps the rest of the code testable without a real device.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class AdbError(RuntimeError):
    """Raised when adb returns a non-zero exit code."""


@dataclass(frozen=True)
class DeviceEntry:
    serial: str
    state: str  # "device", "unauthorized", "offline", "no permissions", ...


def adb_available() -> str | None:
    """Return the path to the `adb` binary if found in PATH, else None."""
    return shutil.which("adb")


def list_devices(timeout: int = 5) -> list[DeviceEntry]:
    """Return the list of devices currently visible to ADB."""
    out = _run(["adb", "devices"], timeout=timeout)
    return parse_devices(out)


def parse_devices(output: str) -> list[DeviceEntry]:
    """Parse the output of `adb devices` into DeviceEntry objects."""
    lines = output.splitlines()
    devices: list[DeviceEntry] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 2:
            continue
        devices.append(DeviceEntry(serial=parts[0], state=parts[1]))
    return devices


def run_shell(serial: str, command: str, timeout: int = 30) -> str:
    """Run `adb -s <serial> shell <command>` and return stdout.

    Raises AdbError on non-zero exit.
    """
    return _run(["adb", "-s", serial, "shell", command], timeout=timeout)


def pull(serial: str, remote_path: str, local_path: str, timeout: int = 30) -> str:
    """Run `adb -s <serial> pull <remote> <local>`."""
    return _run(["adb", "-s", serial, "pull", remote_path, local_path], timeout=timeout)


def adb_version(timeout: int = 5) -> str:
    return _run(["adb", "version"], timeout=timeout)


def _run(args: list[str], *, timeout: int) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AdbError(
            f"`{' '.join(args)}` exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout
