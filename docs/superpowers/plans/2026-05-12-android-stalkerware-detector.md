# Android Stalkerware Detector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI that scans an Android phone connected via USB, detects installed stalkerware via Echap signature matching and permission heuristics, and produces console/JSON/HTML reports with French remediation advice.

**Architecture:** Layered pipeline — `device/` (ADB wrapper, single subprocess boundary) → `collectors/` (parse `dumpsys`/`pm` output into Pydantic models) → `signatures/` (fetch & index Echap IOCs) → `analyzers/` (signature match + permission risk scoring) → `remediation/` + `reporters/` (advise + render). All collectors mockable at the `adb.run_shell()` text-in/text-out level; no subprocess mocks in tests.

**Tech Stack:** Python 3.11+, Typer, Pydantic v2, rich, Jinja2, PyYAML, requests, pytest, ruff, Poetry.

**Spec:** `docs/superpowers/specs/2026-05-12-android-stalkerware-detector-design.md`

---

## File Structure

```
stalkerware-detector/
├─ pyproject.toml
├─ README.md
├─ LICENSE
├─ .gitignore
├─ .github/workflows/ci.yml
├─ src/stalkerware_detector/
│  ├─ __init__.py                    # __version__
│  ├─ cli.py                         # Typer app
│  ├─ models.py                      # Pydantic: InstalledApp, Finding, ScanReport, etc.
│  ├─ device/
│  │  ├─ __init__.py
│  │  ├─ adb.py                      # subprocess boundary
│  │  └─ session.py                  # DeviceSession (serial selection, OS info)
│  ├─ collectors/
│  │  ├─ __init__.py
│  │  ├─ packages.py                 # pm list packages parser
│  │  ├─ permissions.py              # dumpsys package parser
│  │  ├─ device_admin.py             # dumpsys device_policy parser
│  │  └─ accessibility.py            # accessibility services parser
│  ├─ signatures/
│  │  ├─ __init__.py
│  │  ├─ fetcher.py                  # clone/pull Echap repo, 24h cache
│  │  ├─ loader.py                   # YAML stix2 -> IOCIndex
│  │  └─ legitimate_apps.yaml        # allowlist
│  ├─ analyzers/
│  │  ├─ __init__.py
│  │  ├─ signature_match.py          # package + cert + apk hash matching
│  │  └─ permission_risk.py          # scoring heuristic + side-channels
│  ├─ remediation/
│  │  ├─ __init__.py
│  │  └─ advisor.py                  # finding -> RemediationAdvice (FR)
│  ├─ reporters/
│  │  ├─ __init__.py
│  │  ├─ console.py                  # rich tables/panels
│  │  ├─ json_report.py
│  │  └─ html_report.py              # Jinja2, inline CSS, no JS
│  └─ templates/
│     └─ report.html.j2
└─ tests/
   ├─ conftest.py
   ├─ fixtures/
   │  ├─ adb/                        # adb command outputs
   │  ├─ dumpsys/                    # dumpsys outputs
   │  └─ echap_mini/                 # mini YAML stix2 corpus
   ├─ test_device_adb.py
   ├─ test_device_session.py
   ├─ test_signatures_fetcher.py
   ├─ test_signatures_loader.py
   ├─ test_collectors_packages.py
   ├─ test_collectors_permissions.py
   ├─ test_collectors_device_admin.py
   ├─ test_collectors_accessibility.py
   ├─ test_analyzers_signature_match.py
   ├─ test_analyzers_permission_risk.py
   ├─ test_remediation_advisor.py
   ├─ test_reporters_console.py
   ├─ test_reporters_json.py
   ├─ test_reporters_html.py
   └─ test_cli.py
```

**Boundary discipline:** only `device/adb.py` calls `subprocess.run(["adb", ...])`. Every other module receives strings (from `adb.run_shell(...)`) and returns Pydantic models. Tests mock `adb.run_shell` to return fixture file contents.

---

## Phase 1 — Skeleton bootable

### Task 1: Bootstrap repository

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE`
- Create: `.github/workflows/ci.yml`
- Modify: `.gitignore` (already exists from spec commit)
- Modify: `README.md` (already exists from spec commit)
- Create: `src/stalkerware_detector/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[tool.poetry]
name = "stalkerware-detector"
version = "0.1.0"
description = "Scan an Android phone via USB to detect stalkerware (signatures + permission heuristics)."
authors = ["Mathieu Muzelet <mathieu.muzelet@gmail.com>"]
license = "GPL-3.0-or-later"
readme = "README.md"
packages = [{ include = "stalkerware_detector", from = "src" }]

[tool.poetry.dependencies]
python = "^3.11"
typer = "^0.12"
pydantic = "^2.7"
rich = "^13.7"
jinja2 = "^3.1"
pyyaml = "^6.0"
requests = "^2.32"

[tool.poetry.group.dev.dependencies]
pytest = "^8.2"
pytest-cov = "^5.0"
ruff = "^0.5"
syrupy = "^4.6"

[tool.poetry.scripts]
stalkerware-detector = "stalkerware_detector.cli:app"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["requires_device: integration test requiring a real Android device"]
addopts = "-ra --strict-markers"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

- [ ] **Step 2: Write `LICENSE`** — paste the full GPL-3.0 text from <https://www.gnu.org/licenses/gpl-3.0.txt>.

- [ ] **Step 3: Write `src/stalkerware_detector/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Write `tests/__init__.py`** — empty file.

- [ ] **Step 5: Write `tests/conftest.py`**

```python
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    """Load a fixture file as text."""
    def _load(relative: str) -> str:
        return (FIXTURES / relative).read_text(encoding="utf-8")
    return _load


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
```

- [ ] **Step 6: Write `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: pip install poetry
      - run: poetry install --no-interaction
      - run: poetry run ruff check .
      - run: poetry run pytest -q
```

- [ ] **Step 7: Update `README.md`** to include install (`poetry install`) and prerequisites (Android SDK Platform Tools).

- [ ] **Step 8: Install dependencies & verify**

Run: `poetry install`
Expected: `Installing dependencies from lock file` then `Installing the current project: stalkerware-detector`.

Run: `poetry run pytest -q`
Expected: `no tests ran` (no tests yet) but exits 5 or 0; either is acceptable here.

Run: `poetry run ruff check .`
Expected: `All checks passed!`

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml poetry.lock LICENSE .github src tests README.md
git commit -m "chore: bootstrap poetry project, CI, license"
```

---

### Task 2: `device/adb.py` — subprocess boundary

**Files:**
- Create: `src/stalkerware_detector/device/__init__.py`
- Create: `src/stalkerware_detector/device/adb.py`
- Create: `tests/test_device_adb.py`
- Create: `tests/fixtures/adb/devices_one.txt`
- Create: `tests/fixtures/adb/devices_multi.txt`
- Create: `tests/fixtures/adb/devices_unauthorized.txt`
- Create: `tests/fixtures/adb/devices_empty.txt`

- [ ] **Step 1: Write fixture files**

`tests/fixtures/adb/devices_empty.txt`:
```
List of devices attached

```

`tests/fixtures/adb/devices_one.txt`:
```
List of devices attached
ABCD1234EFGH	device

```

`tests/fixtures/adb/devices_multi.txt`:
```
List of devices attached
ABCD1234EFGH	device
WXYZ5678PQRS	device

```

`tests/fixtures/adb/devices_unauthorized.txt`:
```
List of devices attached
ABCD1234EFGH	unauthorized

```

- [ ] **Step 2: Write the failing tests in `tests/test_device_adb.py`**

```python
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
    with patch("stalkerware_detector.device.adb.subprocess.run", return_value=fake_result):
        with pytest.raises(adb.AdbError) as exc:
            adb.run_shell("ABCD1234", "false", timeout=5)
    assert "boom" in str(exc.value)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `poetry run pytest tests/test_device_adb.py -v`
Expected: ImportError / module `stalkerware_detector.device` not found.

- [ ] **Step 4: Write minimal implementation**

`src/stalkerware_detector/device/__init__.py`: empty file.

`src/stalkerware_detector/device/adb.py`:

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_device_adb.py -v`
Expected: all 8 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/device tests/test_device_adb.py tests/fixtures/adb
git commit -m "feat(device): adb subprocess wrapper with parse_devices/run_shell/pull"
```

---

### Task 3: `device/session.py` — device selection and OS info capture

**Files:**
- Create: `src/stalkerware_detector/device/session.py`
- Create: `tests/test_device_session.py`
- Create: `tests/fixtures/adb/getprop.txt`

- [ ] **Step 1: Write `tests/fixtures/adb/getprop.txt`** (a minimal but realistic getprop output)

```
[ro.build.version.release]: [13]
[ro.build.version.sdk]: [33]
[ro.build.id]: [TQ3A.230805.001]
[ro.build.version.security_patch]: [2026-04-05]
[ro.product.manufacturer]: [Google]
[ro.product.model]: [Pixel 7]
```

- [ ] **Step 2: Write the failing tests in `tests/test_device_session.py`**

```python
from unittest.mock import patch

import pytest

from stalkerware_detector.device import adb, session


def test_parse_getprop_extracts_known_keys(fixture_text):
    info = session.parse_getprop(fixture_text("adb/getprop.txt"))
    assert info.android_release == "13"
    assert info.sdk_int == 33
    assert info.build_id == "TQ3A.230805.001"
    assert info.security_patch == "2026-04-05"
    assert info.manufacturer == "Google"
    assert info.model == "Pixel 7"


def test_redact_serial_keeps_last_four():
    assert session.redact_serial("ABCD1234EFGH") == "********EFGH"
    assert session.redact_serial("abc") == "abc"


def test_select_device_picks_only_one():
    devices = [adb.DeviceEntry(serial="X", state="device")]
    assert session.select_device(devices, requested=None, interactive=False) == "X"


def test_select_device_uses_requested_serial():
    devices = [
        adb.DeviceEntry(serial="A", state="device"),
        adb.DeviceEntry(serial="B", state="device"),
    ]
    assert session.select_device(devices, requested="B", interactive=False) == "B"


def test_select_device_requested_not_found_raises():
    devices = [adb.DeviceEntry(serial="A", state="device")]
    with pytest.raises(session.DeviceSelectionError):
        session.select_device(devices, requested="Z", interactive=False)


def test_select_device_no_devices_raises():
    with pytest.raises(session.NoDeviceError):
        session.select_device([], requested=None, interactive=False)


def test_select_device_multi_non_interactive_raises():
    devices = [
        adb.DeviceEntry(serial="A", state="device"),
        adb.DeviceEntry(serial="B", state="device"),
    ]
    with pytest.raises(session.AmbiguousDeviceError):
        session.select_device(devices, requested=None, interactive=False)


def test_select_device_unauthorized_raises():
    devices = [adb.DeviceEntry(serial="A", state="unauthorized")]
    with pytest.raises(session.DeviceUnauthorizedError):
        session.select_device(devices, requested=None, interactive=False)


def test_connect_returns_device_session(fixture_text, monkeypatch):
    monkeypatch.setattr(
        adb, "list_devices", lambda: [adb.DeviceEntry(serial="ABCD1234EFGH", state="device")]
    )
    monkeypatch.setattr(adb, "run_shell", lambda s, c, timeout=30: fixture_text("adb/getprop.txt"))
    sess = session.connect(requested_serial=None, interactive=False)
    assert sess.serial == "ABCD1234EFGH"
    assert sess.info.model == "Pixel 7"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `poetry run pytest tests/test_device_session.py -v`
Expected: ModuleNotFoundError on `stalkerware_detector.device.session`.

- [ ] **Step 4: Write implementation**

`src/stalkerware_detector/device/session.py`:

```python
"""Pick the right device, capture its OS metadata, expose a DeviceSession."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import adb


class DeviceSelectionError(RuntimeError):
    """Base class for device selection failures."""


class NoDeviceError(DeviceSelectionError):
    pass


class AmbiguousDeviceError(DeviceSelectionError):
    pass


class DeviceUnauthorizedError(DeviceSelectionError):
    pass


@dataclass(frozen=True)
class DeviceInfo:
    manufacturer: str | None
    model: str | None
    android_release: str | None
    sdk_int: int | None
    build_id: str | None
    security_patch: str | None


@dataclass(frozen=True)
class DeviceSession:
    serial: str
    info: DeviceInfo


_GETPROP_LINE = re.compile(r"^\[(?P<key>[^\]]+)\]:\s*\[(?P<val>[^\]]*)\]\s*$")


def parse_getprop(output: str) -> DeviceInfo:
    props: dict[str, str] = {}
    for line in output.splitlines():
        m = _GETPROP_LINE.match(line)
        if m:
            props[m.group("key")] = m.group("val")
    sdk_raw = props.get("ro.build.version.sdk")
    return DeviceInfo(
        manufacturer=props.get("ro.product.manufacturer"),
        model=props.get("ro.product.model"),
        android_release=props.get("ro.build.version.release"),
        sdk_int=int(sdk_raw) if sdk_raw and sdk_raw.isdigit() else None,
        build_id=props.get("ro.build.id"),
        security_patch=props.get("ro.build.version.security_patch"),
    )


def redact_serial(serial: str) -> str:
    if len(serial) <= 4:
        return serial
    return ("*" * (len(serial) - 4)) + serial[-4:]


def select_device(
    devices: list[adb.DeviceEntry],
    *,
    requested: str | None,
    interactive: bool,
) -> str:
    if not devices:
        raise NoDeviceError("No device connected. Plug your phone via USB and enable USB debugging.")

    if requested is not None:
        for d in devices:
            if d.serial == requested:
                if d.state == "device":
                    return d.serial
                raise _raise_for_state(d)
        raise DeviceSelectionError(
            f"Requested serial {requested!r} not connected. Seen: "
            f"{[d.serial for d in devices]}"
        )

    if len(devices) == 1:
        d = devices[0]
        if d.state == "device":
            return d.serial
        raise _raise_for_state(d)

    if not interactive:
        raise AmbiguousDeviceError(
            f"{len(devices)} devices connected, use --serial to choose one of "
            f"{[d.serial for d in devices]}"
        )

    raise AmbiguousDeviceError("Interactive selection not implemented in v0.1; pass --serial")


def _raise_for_state(d: adb.DeviceEntry) -> DeviceSelectionError:
    if d.state == "unauthorized":
        return DeviceUnauthorizedError(
            f"Device {d.serial} is unauthorized. Confirm the RSA fingerprint prompt on your phone."
        )
    return DeviceSelectionError(f"Device {d.serial} is in state {d.state!r}.")


def connect(*, requested_serial: str | None, interactive: bool) -> DeviceSession:
    devices = adb.list_devices()
    serial = select_device(devices, requested=requested_serial, interactive=interactive)
    info = parse_getprop(adb.run_shell(serial, "getprop"))
    return DeviceSession(serial=serial, info=info)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_device_session.py -v`
Expected: all 9 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/device/session.py tests/test_device_session.py tests/fixtures/adb/getprop.txt
git commit -m "feat(device): DeviceSession with selection rules and getprop parsing"
```

---

### Task 4: CLI bootstrap — `doctor` and `version` commands

**Files:**
- Create: `src/stalkerware_detector/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests in `tests/test_cli.py`**

```python
from typer.testing import CliRunner

from stalkerware_detector import __version__
from stalkerware_detector.cli import app
from stalkerware_detector.device import adb

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/test_cli.py -v`
Expected: ImportError on `stalkerware_detector.cli`.

- [ ] **Step 3: Write `src/stalkerware_detector/cli.py`**

```python
"""Command-line interface — Typer app."""
from __future__ import annotations

import sys

import typer
from rich.console import Console

from . import __version__
from .device import adb, session

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()


@app.command()
def version() -> None:
    """Print the tool version."""
    console.print(f"stalkerware-detector {__version__}")


@app.command()
def doctor() -> None:
    """Check that adb is installed, a device is connected, and basic info is reachable."""
    adb_path = adb.adb_available()
    if adb_path is None:
        console.print(
            "[red]adb introuvable dans le PATH.[/red]\n"
            "Installer Android SDK Platform Tools : "
            "https://developer.android.com/tools/releases/platform-tools"
        )
        raise typer.Exit(code=10)
    console.print(f"[green]adb[/green] : {adb_path}")
    console.print(adb.adb_version().strip())

    devices = adb.list_devices()
    if not devices:
        console.print(
            "[red]Aucun device connecté.[/red]\n"
            "1. Brancher le câble USB.\n"
            "2. Activer le débogage USB (Options développeur).\n"
            "3. Autoriser la clé RSA sur l'écran du téléphone."
        )
        raise typer.Exit(code=11)

    for d in devices:
        if d.state == "unauthorized":
            console.print(
                f"[yellow]{session.redact_serial(d.serial)}[/yellow] : "
                "non autorisé — valider l'invite RSA sur le téléphone."
            )
            raise typer.Exit(code=12)
        if d.state != "device":
            console.print(
                f"[yellow]{session.redact_serial(d.serial)}[/yellow] : état {d.state!r}"
            )
            raise typer.Exit(code=13)

    sess = session.connect(requested_serial=None, interactive=False)
    console.print(
        f"[green]device[/green] : {session.redact_serial(sess.serial)} — "
        f"{sess.info.manufacturer} {sess.info.model} "
        f"(Android {sess.info.android_release}, patch {sess.info.security_patch})"
    )


def main() -> None:
    try:
        app()
    except session.DeviceUnauthorizedError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(12)
    except session.NoDeviceError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(11)
    except session.AmbiguousDeviceError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(14)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_cli.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 5: Smoke-test with a real device** (if one is connected)

Run: `poetry run stalkerware-detector doctor`
Expected: shows model + Android version + redacted serial.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/cli.py tests/test_cli.py
git commit -m "feat(cli): typer app with version + doctor commands"
```

---

### Task 5: `signatures/fetcher.py` — clone/pull Echap with 24 h cache

**Files:**
- Create: `src/stalkerware_detector/signatures/__init__.py`
- Create: `src/stalkerware_detector/signatures/fetcher.py`
- Create: `tests/test_signatures_fetcher.py`

- [ ] **Step 1: Write `src/stalkerware_detector/signatures/__init__.py`** — empty file.

- [ ] **Step 2: Write the failing tests in `tests/test_signatures_fetcher.py`**

```python
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from stalkerware_detector.signatures import fetcher


def test_default_cache_dir_is_under_user_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert fetcher.default_cache_dir() == tmp_path / "stalkerware-detector" / "echap"


def test_is_fresh_false_when_no_meta(tmp_path):
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is False


def test_is_fresh_true_when_meta_recent(tmp_path):
    meta = {"fetched_at": time.time(), "commit": "abc"}
    (tmp_path / ".meta.json").write_text(json.dumps(meta))
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is True


def test_is_fresh_false_when_meta_stale(tmp_path):
    meta = {"fetched_at": time.time() - 90000, "commit": "abc"}
    (tmp_path / ".meta.json").write_text(json.dumps(meta))
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is False


def test_ensure_fresh_clones_when_missing(tmp_path):
    target = tmp_path / "echap"

    def fake_git(args, cwd=None):
        # Simulate `git clone` creating the target dir
        if args[0:2] == ["clone", fetcher.ECHAP_REPO_URL]:
            Path(args[2]).mkdir(parents=True, exist_ok=True)
            (Path(args[2]) / "README.md").write_text("echap")
            return "Cloning..."
        if args[0:3] == ["rev-parse", "HEAD"]:
            return "deadbeef\n"
        return ""

    with patch.object(fetcher, "_git", side_effect=fake_git):
        meta = fetcher.ensure_fresh(target, allow_network=True)
    assert (target / "README.md").exists()
    assert meta.commit == "deadbeef"


def test_ensure_fresh_skips_when_cache_is_fresh(tmp_path):
    target = tmp_path / "echap"
    target.mkdir()
    (target / ".meta.json").write_text(
        json.dumps({"fetched_at": time.time(), "commit": "stale-but-fresh"})
    )
    with patch.object(fetcher, "_git") as git:
        meta = fetcher.ensure_fresh(target, allow_network=True)
    git.assert_not_called()
    assert meta.commit == "stale-but-fresh"


def test_ensure_fresh_no_network_raises_when_no_cache(tmp_path):
    target = tmp_path / "echap"
    with pytest.raises(fetcher.SignatureCacheError):
        fetcher.ensure_fresh(target, allow_network=False)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `poetry run pytest tests/test_signatures_fetcher.py -v`
Expected: ModuleNotFoundError on `fetcher`.

- [ ] **Step 4: Write `src/stalkerware_detector/signatures/fetcher.py`**

```python
"""Fetch and cache the AssoEchap/stalkerware-indicators repository.

Strategy: a plain `git clone` into a cache dir, then `git pull` if the cache TTL
expired. We store a small `.meta.json` next to the repo for quick freshness
checks without invoking git.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

ECHAP_REPO_URL = "https://github.com/AssoEchap/stalkerware-indicators.git"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class SignatureCacheError(RuntimeError):
    pass


@dataclass(frozen=True)
class IndexMeta:
    fetched_at: float
    commit: str


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "stalkerware-detector" / "echap"
    return Path.home() / ".cache" / "stalkerware-detector" / "echap"


def is_fresh(target: Path, *, ttl_seconds: int) -> bool:
    meta_path = target / ".meta.json"
    if not meta_path.exists():
        return False
    try:
        meta = json.loads(meta_path.read_text())
    except json.JSONDecodeError:
        return False
    fetched_at = float(meta.get("fetched_at", 0))
    return (time.time() - fetched_at) < ttl_seconds


def ensure_fresh(
    target: Path,
    *,
    allow_network: bool = True,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    force: bool = False,
) -> IndexMeta:
    """Make sure `target` contains an up-to-date clone of the Echap repo.

    - If the cache is fresh (or force=False and TTL not expired) and the dir
      exists, do nothing and return the cached meta.
    - Otherwise clone (if missing) or `git pull` (if present).
    - If `allow_network=False` and no cache, raise SignatureCacheError.
    """
    cache_exists = target.exists() and any(target.iterdir())

    if cache_exists and not force and is_fresh(target, ttl_seconds=ttl_seconds):
        return _read_meta(target)

    if not allow_network:
        if not cache_exists:
            raise SignatureCacheError(
                f"No cached signature index at {target} and --no-network was set."
            )
        return _read_meta(target)

    if not cache_exists:
        target.parent.mkdir(parents=True, exist_ok=True)
        _git(["clone", ECHAP_REPO_URL, str(target)])
    else:
        _git(["pull", "--ff-only"], cwd=str(target))

    commit = _git(["rev-parse", "HEAD"], cwd=str(target)).strip()
    meta = IndexMeta(fetched_at=time.time(), commit=commit)
    _write_meta(target, meta)
    return meta


def _read_meta(target: Path) -> IndexMeta:
    meta_path = target / ".meta.json"
    if not meta_path.exists():
        return IndexMeta(fetched_at=0.0, commit="unknown")
    data = json.loads(meta_path.read_text())
    return IndexMeta(fetched_at=float(data["fetched_at"]), commit=str(data.get("commit", "unknown")))


def _write_meta(target: Path, meta: IndexMeta) -> None:
    (target / ".meta.json").write_text(
        json.dumps({"fetched_at": meta.fetched_at, "commit": meta.commit})
    )


def _git(args: list[str], *, cwd: str | None = None) -> str:
    cmd = ["git", *args]
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SignatureCacheError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_signatures_fetcher.py -v`
Expected: all 7 tests PASS.

- [ ] **Step 6: Add `update-sigs` command to `cli.py`**

Add this to `cli.py`:

```python
@app.command("update-sigs")
def update_sigs(force: bool = typer.Option(True, help="Ignore the 24h cache and refresh now.")) -> None:
    """Fetch the latest Echap signature index."""
    from .signatures import fetcher

    target = fetcher.default_cache_dir()
    meta = fetcher.ensure_fresh(target, allow_network=True, force=force)
    console.print(f"[green]signature index[/green] : {target}")
    console.print(f"commit : {meta.commit}")
```

- [ ] **Step 7: Smoke-test update-sigs**

Run: `poetry run stalkerware-detector update-sigs`
Expected: prints commit hash, dir exists with YAML files inside.

- [ ] **Step 8: Commit**

```bash
git add src/stalkerware_detector/signatures src/stalkerware_detector/cli.py tests/test_signatures_fetcher.py
git commit -m "feat(signatures): fetcher with 24h cache + update-sigs command"
```

---

## Phase 2 — Signature-based detection

### Task 6: `models.py` — Pydantic models

**Files:**
- Create: `src/stalkerware_detector/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write the failing tests in `tests/test_models.py`**

```python
import pytest
from pydantic import ValidationError

from stalkerware_detector import models


def test_finding_critical_requires_safety_first():
    with pytest.raises(ValidationError):
        models.Finding(
            id="x",
            severity=models.Severity.CRITICAL,
            kind=models.FindingKind.SIGNATURE_HIT,
            target_package="com.example.spy",
            summary="match",
            details="...",
            evidence={},
            remediation=models.RemediationAdvice(
                risk_summary="...", safety_first="", steps=[], helplines=[]
            ),
        )


def test_finding_low_allows_empty_safety_first():
    f = models.Finding(
        id="x",
        severity=models.Severity.LOW,
        kind=models.FindingKind.SIDELOADED_APP,
        target_package="com.example",
        summary="sideloaded",
        details="...",
        evidence={},
        remediation=models.RemediationAdvice(
            risk_summary="...", safety_first="", steps=[], helplines=[]
        ),
    )
    assert f.severity is models.Severity.LOW


def test_scan_report_summary_counts():
    rep = models.ScanReport(
        schema_version="1.0",
        tool_version="0.1.0",
        device=models.DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33, build_id="X", security_patch="2026-04",
        ),
        signature_index=models.SignatureIndexMeta(commit="abc", fetched_at=1.0),
        findings=[
            _make_finding(models.Severity.CRITICAL),
            _make_finding(models.Severity.HIGH),
            _make_finding(models.Severity.HIGH),
        ],
        safety_warning="...",
    )
    assert rep.summary[models.Severity.CRITICAL] == 1
    assert rep.summary[models.Severity.HIGH] == 2
    assert rep.summary.get(models.Severity.LOW, 0) == 0


def _make_finding(severity):
    return models.Finding(
        id=f"f-{severity.value}",
        severity=severity,
        kind=models.FindingKind.SIGNATURE_HIT,
        target_package="com.spy",
        summary="...",
        details="...",
        evidence={},
        remediation=models.RemediationAdvice(
            risk_summary="risk",
            safety_first="warn" if severity in {models.Severity.CRITICAL, models.Severity.HIGH} else "",
            steps=[],
            helplines=[],
        ),
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/test_models.py -v`
Expected: ModuleNotFoundError on the new symbols.

- [ ] **Step 3: Write `src/stalkerware_detector/models.py`**

```python
"""Pydantic models for the scan report and its components."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingKind(StrEnum):
    SIGNATURE_HIT = "signature_hit"
    PERMISSION_PROFILE = "permission_profile"
    DEVICE_ADMIN = "device_admin"
    ACCESSIBILITY_SVC = "accessibility_service"
    SIDELOADED_APP = "sideloaded_app"
    MDM_DETECTED = "mdm_detected"
    ANALYZER_ERROR = "analyzer_error"
    COLLECT_PARTIAL = "collect_partial"


class InstalledApp(BaseModel):
    package: str
    label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    apk_path: str
    installer_package: str | None = None
    first_install_time: datetime | None = None
    last_update_time: datetime | None = None
    system: bool = False
    enabled: bool = True


class GrantedPermission(BaseModel):
    name: str
    granted: bool = True
    flags: list[str] = Field(default_factory=list)


class Helpline(BaseModel):
    name: str
    phone: str | None = None
    url: str | None = None
    description: str | None = None


class RemediationAdvice(BaseModel):
    risk_summary: str
    safety_first: str = ""
    steps: list[str] = Field(default_factory=list)
    helplines: list[Helpline] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    severity: Severity
    kind: FindingKind
    target_package: str
    target_label: str | None = None
    summary: str
    details: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: RemediationAdvice
    references: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_safety_first_on_high_severity(self) -> Finding:
        if self.severity in {Severity.CRITICAL, Severity.HIGH}:
            if not self.remediation.safety_first.strip():
                raise ValueError(
                    f"Finding {self.id} is {self.severity} but remediation.safety_first is empty"
                )
        return self


class DeviceInfo(BaseModel):
    serial_redacted: str
    manufacturer: str | None = None
    model: str | None = None
    android_release: str | None = None
    sdk_int: int | None = None
    build_id: str | None = None
    security_patch: str | None = None


class SignatureIndexMeta(BaseModel):
    commit: str
    fetched_at: float


class ScanReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    tool_version: str
    device: DeviceInfo
    signature_index: SignatureIndexMeta
    findings: list[Finding] = Field(default_factory=list)
    safety_warning: str = ""

    @computed_field
    @property
    def summary(self) -> dict[Severity, int]:
        return dict(Counter(f.severity for f in self.findings))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_models.py -v`
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stalkerware_detector/models.py tests/test_models.py
git commit -m "feat(models): pydantic schema for findings + scan report with safety-first invariant"
```

---

### Task 7: `collectors/packages.py` — parse `pm list packages`

**Files:**
- Create: `src/stalkerware_detector/collectors/__init__.py`
- Create: `src/stalkerware_detector/collectors/packages.py`
- Create: `tests/test_collectors_packages.py`
- Create: `tests/fixtures/adb/pm_list_packages.txt`
- Create: `tests/fixtures/dumpsys/package_legit.txt`
- Create: `tests/fixtures/dumpsys/package_suspicious.txt`

- [ ] **Step 1: Write `tests/fixtures/adb/pm_list_packages.txt`** (real format of `pm list packages -f -U -i -u`)

```
package:/system/app/Maps/Maps.apk=com.google.android.apps.maps  installer=com.android.vending  uid:10123
package:/data/app/~~AbCdEf==/com.example.spy-1==/base.apk=com.example.spy  installer=null  uid:10456
package:/system/priv-app/SystemUI/SystemUI.apk=com.android.systemui  installer=null  uid:1000
package:/data/app/~~XyZ==/com.android.chrome-1==/base.apk=com.android.chrome  installer=com.android.vending  uid:10789
```

- [ ] **Step 2: Write `tests/fixtures/dumpsys/package_legit.txt`**

```
Package [com.google.android.apps.maps] (1234abcd):
  userId=10123
  pkg=Package{abcd1234 com.google.android.apps.maps}
  codePath=/system/app/Maps
  applicationInfo=ApplicationInfo{ com.google.android.apps.maps}
  flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
  versionName=11.110.0301
  versionCode=11110301
  firstInstallTime=2024-01-01 10:00:00
  lastUpdateTime=2026-04-01 12:00:00
  installerPackageName=com.android.vending
  signatures=PackageSignatures{1234 [a1b2c3d4e5f60708090a0b0c0d0e0f10111213141516171819202122232425262]}
  install permissions:
    android.permission.INTERNET: granted=true
  runtime permissions:
    android.permission.ACCESS_FINE_LOCATION: granted=true
```

- [ ] **Step 3: Write `tests/fixtures/dumpsys/package_suspicious.txt`**

```
Package [com.example.spy] (deadbeef):
  userId=10456
  pkg=Package{def0 com.example.spy}
  codePath=/data/app/~~AbCdEf==/com.example.spy-1==
  applicationInfo=ApplicationInfo{ com.example.spy}
  flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
  versionName=2.5.1
  versionCode=251
  firstInstallTime=2026-04-30 22:15:00
  lastUpdateTime=2026-04-30 22:15:00
  installerPackageName=null
  signatures=PackageSignatures{99 [babe1234babe1234babe1234babe1234babe1234babe1234babe1234babe1234]}
  install permissions:
    android.permission.RECEIVE_BOOT_COMPLETED: granted=true
  runtime permissions:
    android.permission.RECORD_AUDIO: granted=true
    android.permission.ACCESS_FINE_LOCATION: granted=true
    android.permission.ACCESS_BACKGROUND_LOCATION: granted=true
    android.permission.READ_SMS: granted=true
    android.permission.READ_CONTACTS: granted=true
    android.permission.READ_CALL_LOG: granted=true
```

- [ ] **Step 4: Write the failing tests in `tests/test_collectors_packages.py`**

```python
from unittest.mock import patch

from stalkerware_detector.collectors import packages
from stalkerware_detector.device import adb


def test_parse_pm_list_extracts_apk_path_package_installer(fixture_text):
    apps = packages.parse_pm_list(fixture_text("adb/pm_list_packages.txt"))
    by_pkg = {a.package: a for a in apps}

    maps = by_pkg["com.google.android.apps.maps"]
    assert maps.apk_path == "/system/app/Maps/Maps.apk"
    assert maps.installer_package == "com.android.vending"

    spy = by_pkg["com.example.spy"]
    assert spy.apk_path.endswith("/base.apk")
    assert spy.installer_package is None


def test_classify_system_paths():
    assert packages.is_system_path("/system/app/Maps/Maps.apk") is True
    assert packages.is_system_path("/system/priv-app/SystemUI/SystemUI.apk") is True
    assert packages.is_system_path("/data/app/~~Ab/com.example-1==/base.apk") is False


def test_enrich_with_dumpsys_fills_versions_and_dates(fixture_text):
    app = packages.InstalledApp(
        package="com.example.spy",
        apk_path="/data/app/~~AbCdEf==/com.example.spy-1==/base.apk",
        installer_package=None,
    )
    enriched = packages.enrich_with_dumpsys(app, fixture_text("dumpsys/package_suspicious.txt"))
    assert enriched.version_name == "2.5.1"
    assert enriched.version_code == 251
    assert enriched.first_install_time is not None
    assert enriched.last_update_time is not None


def test_collect_uses_adb_run_shell(monkeypatch, fixture_text):
    calls = []

    def fake_run(serial, cmd, timeout=30):
        calls.append(cmd)
        if cmd.startswith("pm list packages"):
            return fixture_text("adb/pm_list_packages.txt")
        if cmd.startswith("dumpsys package "):
            pkg = cmd.split()[-1]
            if pkg == "com.example.spy":
                return fixture_text("dumpsys/package_suspicious.txt")
            return fixture_text("dumpsys/package_legit.txt")
        return ""

    monkeypatch.setattr(adb, "run_shell", fake_run)
    apps = packages.collect("ABCD")
    assert {a.package for a in apps} == {
        "com.google.android.apps.maps",
        "com.example.spy",
        "com.android.systemui",
        "com.android.chrome",
    }
    by_pkg = {a.package: a for a in apps}
    assert by_pkg["com.example.spy"].version_name == "2.5.1"
    assert by_pkg["com.android.systemui"].system is True
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `poetry run pytest tests/test_collectors_packages.py -v`
Expected: ModuleNotFoundError on `collectors.packages`.

- [ ] **Step 6: Write implementation**

`src/stalkerware_detector/collectors/__init__.py`: empty file.

`src/stalkerware_detector/collectors/packages.py`:

```python
"""Collect the list of installed packages, with metadata."""
from __future__ import annotations

import re
from datetime import datetime

from ..device import adb
from ..models import InstalledApp

# `pm list packages -f -U -i -u` lines look like:
#   package:/path/base.apk=com.pkg.name  installer=com.android.vending  uid:10123
_PM_LIST_LINE = re.compile(
    r"^package:(?P<apk_path>[^=]+)=(?P<package>[A-Za-z0-9_.]+)"
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
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `poetry run pytest tests/test_collectors_packages.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add src/stalkerware_detector/collectors tests/test_collectors_packages.py tests/fixtures/adb/pm_list_packages.txt tests/fixtures/dumpsys
git commit -m "feat(collectors): packages collector (pm list + dumpsys enrich)"
```

---

### Task 8: `signatures/loader.py` — index Echap YAML into IOC lookups

**Note on the Echap format:** files in `stalkerware-indicators/samples/*.yaml` follow STIX2-like schemas. The fields we care about per sample are:
```yaml
name: cerberus
type: stalkerware
apps:
  - id: com.cerberusapp
    certificates:
      - "a1b2c3d4..."
    sha256:
      - "11aa22bb..."
```

We will normalize this into a lookup table: `{package_name -> SampleIOC, cert_sha256 -> SampleIOC, apk_sha256 -> SampleIOC}`.

**Files:**
- Create: `src/stalkerware_detector/signatures/loader.py`
- Create: `tests/test_signatures_loader.py`
- Create: `tests/fixtures/echap_mini/samples/cerberus.yaml`
- Create: `tests/fixtures/echap_mini/samples/mspy.yaml`
- Create: `tests/fixtures/echap_mini/samples/broken.yaml`

- [ ] **Step 1: Write fixture YAMLs**

`tests/fixtures/echap_mini/samples/cerberus.yaml`:
```yaml
name: cerberus
type: stalkerware
apps:
  - id: com.lsdroid.cerberus
    name: Cerberus
    certificates:
      - "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
    sha256:
      - "1111111111111111111111111111111111111111111111111111111111111111"
      - "2222222222222222222222222222222222222222222222222222222222222222"
references:
  - https://example.org/cerberus
```

`tests/fixtures/echap_mini/samples/mspy.yaml`:
```yaml
name: mspy
type: stalkerware
apps:
  - id: com.mspy.android
    certificates:
      - "ffffeeeeddddccccbbbbaaaa99998888777766665555444433332222111100ff"
    sha256: []
```

`tests/fixtures/echap_mini/samples/broken.yaml`:
```yaml
this is: not a sample
```

- [ ] **Step 2: Write the failing tests in `tests/test_signatures_loader.py`**

```python
import pytest

from stalkerware_detector.signatures import loader


def test_load_index_from_dir_indexes_packages(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "com.lsdroid.cerberus" in index.by_package
    assert "com.mspy.android" in index.by_package
    assert len(index.by_package) == 2


def test_load_index_indexes_certs_case_insensitive(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    # cert is uppercase in the YAML; queries should be lowercased
    assert "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" in index.by_cert


def test_load_index_indexes_apk_hashes(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "1" * 64 in index.by_sha256
    assert "2" * 64 in index.by_sha256


def test_load_index_skips_broken_yaml_with_warning(fixtures_dir, caplog):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "broken" not in {ioc.name for ioc in index.by_package.values()}
    assert any("broken.yaml" in rec.message for rec in caplog.records)


def test_match_package_returns_ioc(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    hit = index.match_package("com.lsdroid.cerberus")
    assert hit is not None
    assert hit.name == "cerberus"


def test_match_cert_is_case_insensitive(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    hit = index.match_cert("AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899")
    assert hit is not None
    assert hit.name == "cerberus"


def test_match_unknown_returns_none(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert index.match_package("com.unknown") is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `poetry run pytest tests/test_signatures_loader.py -v`
Expected: ModuleNotFoundError on `loader`.

- [ ] **Step 4: Write `src/stalkerware_detector/signatures/loader.py`**

```python
"""Load YAML signature samples (Echap format) into a fast lookup index."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SampleIOC:
    name: str
    type: str
    package: str
    certificates: tuple[str, ...] = ()
    apk_hashes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    source_path: str = ""


@dataclass
class IOCIndex:
    by_package: dict[str, SampleIOC] = field(default_factory=dict)
    by_cert: dict[str, SampleIOC] = field(default_factory=dict)
    by_sha256: dict[str, SampleIOC] = field(default_factory=dict)

    def match_package(self, package: str) -> SampleIOC | None:
        return self.by_package.get(package)

    def match_cert(self, cert_sha256: str) -> SampleIOC | None:
        return self.by_cert.get(cert_sha256.lower())

    def match_apk_sha256(self, sha256: str) -> SampleIOC | None:
        return self.by_sha256.get(sha256.lower())


def load_index(root: Path) -> IOCIndex:
    """Walk `root/samples/*.yaml` and build an IOCIndex."""
    index = IOCIndex()
    samples_dir = root / "samples"
    candidates = list(samples_dir.glob("*.yaml")) if samples_dir.exists() else list(root.glob("**/*.yaml"))
    for yaml_path in candidates:
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            log.warning("Failed to parse %s: %s", yaml_path, e)
            continue
        if not isinstance(data, dict) or "apps" not in data:
            log.warning("Skipping %s: no 'apps' key", yaml_path)
            continue
        name = str(data.get("name") or yaml_path.stem)
        sample_type = str(data.get("type") or "stalkerware")
        references = tuple(str(r) for r in data.get("references", []) or [])
        for app in data.get("apps", []) or []:
            if not isinstance(app, dict):
                continue
            package = app.get("id")
            if not package:
                continue
            ioc = SampleIOC(
                name=name,
                type=sample_type,
                package=str(package),
                certificates=tuple(str(c).lower() for c in app.get("certificates", []) or []),
                apk_hashes=tuple(str(h).lower() for h in app.get("sha256", []) or []),
                references=references,
                source_path=str(yaml_path),
            )
            index.by_package[ioc.package] = ioc
            for cert in ioc.certificates:
                index.by_cert[cert] = ioc
            for sha in ioc.apk_hashes:
                index.by_sha256[sha] = ioc
    return index
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_signatures_loader.py -v`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/signatures/loader.py tests/test_signatures_loader.py tests/fixtures/echap_mini
git commit -m "feat(signatures): YAML loader + IOCIndex with package/cert/sha256 lookups"
```

---

### Task 9: `analyzers/signature_match.py` — match installed apps against IOCIndex

In this phase we match on **package name** and **certificate fingerprint** only. APK hashing is deferred to Task 19.

**Files:**
- Create: `src/stalkerware_detector/analyzers/__init__.py`
- Create: `src/stalkerware_detector/analyzers/signature_match.py`
- Create: `src/stalkerware_detector/collectors/cert.py` (helper to extract cert fingerprint from dumpsys)
- Create: `tests/test_analyzers_signature_match.py`

- [ ] **Step 1: Write `src/stalkerware_detector/collectors/cert.py`**

```python
"""Extract certificate SHA-256 fingerprints from `dumpsys package` output."""
from __future__ import annotations

import hashlib
import re

# `dumpsys package` lines (Android >= 9) include:
#   signatures=PackageSignatures{<id> [<hex_blob>]}
# where <hex_blob> is the DER-encoded cert(s). We hash the blob to SHA-256.
_SIG_BLOCK = re.compile(
    r"signatures=PackageSignatures\{[^[]*\[(?P<blob>[0-9a-fA-F, ]+)\]\}"
)


def extract_cert_sha256(dump: str) -> list[str]:
    """Return list of SHA-256 hex strings (lowercase) for the cert blobs found."""
    out: list[str] = []
    for m in _SIG_BLOCK.finditer(dump):
        hex_blob = m.group("blob").replace(" ", "").replace(",", "")
        try:
            data = bytes.fromhex(hex_blob)
        except ValueError:
            continue
        out.append(hashlib.sha256(data).hexdigest())
    return out
```

- [ ] **Step 2: Write `src/stalkerware_detector/analyzers/__init__.py`** — empty file.

- [ ] **Step 3: Write the failing tests in `tests/test_analyzers_signature_match.py`**

```python
from stalkerware_detector.analyzers import signature_match
from stalkerware_detector.models import FindingKind, InstalledApp, Severity
from stalkerware_detector.signatures import loader


def test_match_by_package_emits_critical_finding(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.lsdroid.cerberus",
            apk_path="/data/app/x/base.apk",
            installer_package=None,
        )
    ]
    findings = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.kind is FindingKind.SIGNATURE_HIT
    assert f.evidence["matched_on"] == "package"
    assert f.evidence["ioc_name"] == "cerberus"
    assert f.remediation.safety_first  # non-empty


def test_match_by_cert_when_package_unknown(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.renamed.example",
            apk_path="/data/app/x/base.apk",
            installer_package=None,
        )
    ]
    certs = {
        "com.renamed.example": [
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        ]
    }
    findings = signature_match.analyze(apps=apps, certs_by_pkg=certs, index=index)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["matched_on"] == "cert"


def test_no_match_emits_no_findings(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.android.chrome",
            apk_path="/data/app/x/base.apk",
            installer_package="com.android.vending",
        )
    ]
    findings = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert findings == []


def test_finding_id_is_stable(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(
            package="com.lsdroid.cerberus",
            apk_path="/data/app/x/base.apk",
        )
    ]
    a = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    b = signature_match.analyze(apps=apps, certs_by_pkg={}, index=index)
    assert a[0].id == b[0].id
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `poetry run pytest tests/test_analyzers_signature_match.py -v`
Expected: ModuleNotFoundError on `analyzers.signature_match`.

- [ ] **Step 5: Write `src/stalkerware_detector/analyzers/signature_match.py`**

```python
"""Match installed apps against the Echap IOC index (package + cert phase)."""
from __future__ import annotations

import hashlib

from ..models import Finding, FindingKind, Helpline, InstalledApp, RemediationAdvice, Severity
from ..signatures.loader import IOCIndex, SampleIOC

_HELP_FR_HIGH = [
    Helpline(
        name="3919 — Violences faites aux femmes",
        phone="3919",
        url="https://www.solidaritefemmes.org/",
        description="Gratuit, anonyme, 24/7.",
    ),
    Helpline(
        name="17 — Police-secours",
        phone="17",
        description="En cas de danger immédiat.",
    ),
]

_SAFETY_FIRST_FR = (
    "Avant de désinstaller : la disparition du logiciel peut alerter la personne "
    "qui l'a installé. Contacter le 3919 (gratuit, anonyme) ou la police (17) si "
    "vous êtes en danger immédiat. Conserver ce rapport comme preuve."
)


def analyze(
    *,
    apps: list[InstalledApp],
    certs_by_pkg: dict[str, list[str]],
    index: IOCIndex,
) -> list[Finding]:
    """Return findings for apps matching a known stalkerware IOC."""
    findings: list[Finding] = []
    for app in apps:
        ioc = index.match_package(app.package)
        matched_on = "package"
        matched_value: str = app.package

        if ioc is None:
            for cert in certs_by_pkg.get(app.package, []):
                hit = index.match_cert(cert)
                if hit is not None:
                    ioc = hit
                    matched_on = "cert"
                    matched_value = cert
                    break

        if ioc is None:
            continue

        findings.append(_build_finding(app, ioc, matched_on, matched_value))
    return findings


def _build_finding(
    app: InstalledApp, ioc: SampleIOC, matched_on: str, matched_value: str
) -> Finding:
    fid = hashlib.sha1(
        f"signature_hit|{app.package}|{matched_on}|{ioc.name}".encode()
    ).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package=app.package,
        target_label=app.label,
        summary=f"Stalkerware connu détecté : {ioc.name}",
        details=(
            f"Le package **{app.package}** correspond à une signature connue de "
            f"stalkerware (**{ioc.name}**) référencée dans la base "
            f"AssoEchap/stalkerware-indicators. Correspondance trouvée par "
            f"**{matched_on}**."
        ),
        evidence={
            "matched_on": matched_on,
            "matched_value": matched_value,
            "ioc_name": ioc.name,
            "ioc_type": ioc.type,
            "source_path": ioc.source_path,
        },
        remediation=RemediationAdvice(
            risk_summary=(
                "Ce type de logiciel peut accéder à la localisation, aux SMS, "
                "aux appels, au micro et à la caméra à l'insu de l'utilisatrice."
            ),
            safety_first=_SAFETY_FIRST_FR,
            steps=[
                "Mettre ce rapport en sécurité (impression, transfert sur un autre appareil de confiance).",
                "Contacter une association d'aide (3919) avant toute action visible.",
                "Désinstaller via Paramètres > Applications > <l'app> > Désinstaller.",
                "Si l'app dispose des droits administrateur, les retirer d'abord dans "
                "Paramètres > Sécurité > Administrateurs de l'appareil.",
                "Changer les mots de passe importants depuis un autre appareil sain.",
                "Envisager une réinitialisation d'usine après extraction des données.",
            ],
            helplines=list(_HELP_FR_HIGH),
        ),
        references=list(ioc.references),
    )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `poetry run pytest tests/test_analyzers_signature_match.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/stalkerware_detector/analyzers src/stalkerware_detector/collectors/cert.py tests/test_analyzers_signature_match.py
git commit -m "feat(analyzers): signature match by package + cert with FR remediation"
```

---

### Task 10: `reporters/console.py` — basic rich rendering

**Files:**
- Create: `src/stalkerware_detector/reporters/__init__.py`
- Create: `src/stalkerware_detector/reporters/console.py`
- Create: `tests/test_reporters_console.py`

- [ ] **Step 1: Write `src/stalkerware_detector/reporters/__init__.py`** — empty file.

- [ ] **Step 2: Write the failing tests in `tests/test_reporters_console.py`**

```python
from io import StringIO

from rich.console import Console

from stalkerware_detector.models import (
    DeviceInfo,
    Finding,
    FindingKind,
    Helpline,
    RemediationAdvice,
    ScanReport,
    Severity,
    SignatureIndexMeta,
)
from stalkerware_detector.reporters import console as console_reporter


def _report(findings):
    return ScanReport(
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH",
            manufacturer="Google",
            model="Pixel 7",
            android_release="13",
            sdk_int=33,
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=findings,
        safety_warning="warn",
    )


def _make_critical(pkg: str) -> Finding:
    return Finding(
        id=f"id-{pkg}",
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package=pkg,
        summary=f"Stalkerware connu détecté : {pkg}",
        details="...",
        evidence={"matched_on": "package"},
        remediation=RemediationAdvice(
            risk_summary="risk",
            safety_first="be careful",
            steps=["step1"],
            helplines=[Helpline(name="3919", phone="3919")],
        ),
    )


def test_render_shows_device_info_and_findings():
    buf = StringIO()
    rich_console = Console(file=buf, force_terminal=False, width=120)
    report = _report([_make_critical("com.spy.one")])
    console_reporter.render(report, rich_console=rich_console)
    out = buf.getvalue()
    assert "Pixel 7" in out
    assert "****EFGH" in out
    assert "com.spy.one" in out
    assert "CRITICAL" in out.upper()


def test_render_no_findings_prints_clean_message():
    buf = StringIO()
    rich_console = Console(file=buf, force_terminal=False, width=120)
    report = _report([])
    console_reporter.render(report, rich_console=rich_console)
    out = buf.getvalue()
    assert "aucun" in out.lower() or "no finding" in out.lower()


def test_compute_exit_code_matches_spec():
    assert console_reporter.compute_exit_code(_report([])) == 0
    low = _make_critical("com.x").model_copy(update={"severity": Severity.LOW})
    low_advice = low.remediation.model_copy(update={"safety_first": ""})
    low = low.model_copy(update={"remediation": low_advice})
    assert console_reporter.compute_exit_code(_report([low])) == 1
    med = low.model_copy(update={"severity": Severity.MEDIUM})
    assert console_reporter.compute_exit_code(_report([med])) == 1
    high = _make_critical("com.x").model_copy(update={"severity": Severity.HIGH})
    assert console_reporter.compute_exit_code(_report([high])) == 2
    crit = _make_critical("com.x")
    assert console_reporter.compute_exit_code(_report([crit])) == 3
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `poetry run pytest tests/test_reporters_console.py -v`
Expected: ModuleNotFoundError on `reporters.console`.

- [ ] **Step 4: Write `src/stalkerware_detector/reporters/console.py`**

```python
"""Render a ScanReport to a rich Console."""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Finding, ScanReport, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def render(report: ScanReport, *, rich_console: Console | None = None) -> None:
    console = rich_console or Console()

    console.print(_device_panel(report))
    if not report.findings:
        console.print(
            Panel.fit(
                "[green]Aucun finding détecté. Aucun stalkerware connu, aucun "
                "profil de permissions suspect.[/green]",
                title="Résultat",
            )
        )
        return

    if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in report.findings):
        console.print(
            Panel(
                Text(report.safety_warning or _DEFAULT_SAFETY, style="bold white on red"),
                title="⚠ AVANT TOUTE ACTION",
                border_style="red",
            )
        )

    table = Table(title="Findings", box=box.SIMPLE_HEAVY)
    table.add_column("Sév.", style="bold")
    table.add_column("Kind")
    table.add_column("Package")
    table.add_column("Summary")
    for f in sorted(report.findings, key=_finding_sort_key):
        table.add_row(
            Text(f.severity.value.upper(), style=_SEVERITY_STYLE[f.severity]),
            f.kind.value,
            f.target_package,
            f.summary,
        )
    console.print(table)

    for f in sorted(report.findings, key=_finding_sort_key):
        if f.severity in {Severity.CRITICAL, Severity.HIGH}:
            console.print(_finding_panel(f))


def _device_panel(report: ScanReport) -> Panel:
    d = report.device
    body = (
        f"[bold]{d.manufacturer} {d.model}[/bold]  —  "
        f"Android {d.android_release} (SDK {d.sdk_int})\n"
        f"Serial : {d.serial_redacted}\n"
        f"Patch  : {d.security_patch}\n"
        f"Sig. index : {report.signature_index.commit}"
    )
    return Panel(body, title="Device", border_style="cyan")


def _finding_panel(f: Finding) -> Panel:
    style = _SEVERITY_STYLE[f.severity]
    body_lines = [
        f"[{style}]{f.severity.value.upper()}[/]  {f.summary}",
        "",
        f.details,
    ]
    if f.remediation.safety_first:
        body_lines += ["", f"[bold red]⚠ {f.remediation.safety_first}[/]"]
    if f.remediation.steps:
        body_lines += ["", "[bold]À faire :[/]"]
        body_lines += [f"  {i+1}. {s}" for i, s in enumerate(f.remediation.steps)]
    if f.remediation.helplines:
        body_lines += ["", "[bold]Aide :[/]"]
        for h in f.remediation.helplines:
            phone = f" — {h.phone}" if h.phone else ""
            body_lines.append(f"  • {h.name}{phone}")
    return Panel("\n".join(body_lines), title=f.target_package, border_style="red")


def _finding_sort_key(f: Finding) -> tuple[int, str]:
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    return (order.index(f.severity), f.target_package)


def compute_exit_code(report: ScanReport) -> int:
    sevs = {f.severity for f in report.findings}
    if Severity.CRITICAL in sevs:
        return 3
    if Severity.HIGH in sevs:
        return 2
    if Severity.MEDIUM in sevs or Severity.LOW in sevs:
        return 1
    return 0


_DEFAULT_SAFETY = (
    "Avant de désinstaller quoi que ce soit : si vous suspectez un harcèlement, "
    "la disparition du stalkerware peut alerter la personne qui l'a installé. "
    "Contactez d'abord le 3919 (gratuit, anonyme) ou la police (17) si vous êtes "
    "en danger immédiat. Conservez ce rapport comme preuve."
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_reporters_console.py -v`
Expected: all 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/reporters tests/test_reporters_console.py
git commit -m "feat(reporters): rich console output with safety-first banner + exit code mapping"
```

---

### Task 11: `scan` command — wire everything together (signatures-only path)

This task adds `scan` to the CLI with **only** the signature-match analyzer wired in. The permission analyzer comes in Phase 3.

**Files:**
- Modify: `src/stalkerware_detector/cli.py`
- Create: `src/stalkerware_detector/scan.py` (orchestration helper, easy to test)
- Create: `tests/test_scan.py`

- [ ] **Step 1: Write the failing tests in `tests/test_scan.py`**

```python
from pathlib import Path
from unittest.mock import MagicMock

from stalkerware_detector import scan
from stalkerware_detector.device import session
from stalkerware_detector.models import FindingKind, InstalledApp, Severity
from stalkerware_detector.signatures.fetcher import IndexMeta


def _make_session():
    info = session.DeviceInfo(
        manufacturer="Google", model="Pixel 7",
        android_release="13", sdk_int=33,
        build_id="X", security_patch="2026-04",
    )
    return session.DeviceSession(serial="ABCD1234EFGH", info=info)


def test_run_scan_returns_report_with_signature_finding(monkeypatch, fixtures_dir):
    sess = _make_session()
    apps = [
        InstalledApp(package="com.lsdroid.cerberus", apk_path="/data/app/x/base.apk"),
        InstalledApp(package="com.android.chrome", apk_path="/data/app/y/base.apk"),
    ]

    monkeypatch.setattr(scan.session, "connect", lambda **kw: sess)
    monkeypatch.setattr(scan.packages, "collect", lambda serial: apps)
    monkeypatch.setattr(scan, "_collect_certs", lambda serial, apps: {})

    fake_fetcher_target = fixtures_dir / "echap_mini"
    monkeypatch.setattr(
        scan.fetcher, "ensure_fresh",
        lambda target, allow_network, force=False: IndexMeta(fetched_at=1.0, commit="abc"),
    )
    monkeypatch.setattr(scan.fetcher, "default_cache_dir", lambda: fake_fetcher_target)

    report = scan.run_scan(serial=None, allow_network=True, interactive=False)
    sigs = [f for f in report.findings if f.kind is FindingKind.SIGNATURE_HIT]
    assert len(sigs) == 1
    assert sigs[0].target_package == "com.lsdroid.cerberus"
    assert sigs[0].severity is Severity.CRITICAL
    assert report.device.serial_redacted.endswith("EFGH")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/test_scan.py -v`
Expected: ModuleNotFoundError on `stalkerware_detector.scan`.

- [ ] **Step 3: Write `src/stalkerware_detector/scan.py`**

```python
"""Top-level scan orchestration: pulled out of cli.py so it stays unit-testable."""
from __future__ import annotations

from . import __version__
from .analyzers import signature_match
from .collectors import cert as cert_collector
from .collectors import packages
from .device import adb, session
from .models import DeviceInfo, InstalledApp, ScanReport, SignatureIndexMeta
from .signatures import fetcher, loader

_DEFAULT_SAFETY = (
    "Avant de désinstaller quoi que ce soit : la disparition du stalkerware peut "
    "alerter la personne qui l'a installé. Contactez d'abord le 3919 ou la police "
    "(17) en danger immédiat. Conservez ce rapport comme preuve."
)


def run_scan(*, serial: str | None, allow_network: bool, interactive: bool) -> ScanReport:
    sess = session.connect(requested_serial=serial, interactive=interactive)

    cache_dir = fetcher.default_cache_dir()
    sig_meta = fetcher.ensure_fresh(cache_dir, allow_network=allow_network)
    index = loader.load_index(cache_dir)

    apps = packages.collect(sess.serial)
    certs_by_pkg = _collect_certs(sess.serial, apps)

    findings = signature_match.analyze(apps=apps, certs_by_pkg=certs_by_pkg, index=index)

    return ScanReport(
        tool_version=__version__,
        device=DeviceInfo(
            serial_redacted=session.redact_serial(sess.serial),
            manufacturer=sess.info.manufacturer,
            model=sess.info.model,
            android_release=sess.info.android_release,
            sdk_int=sess.info.sdk_int,
            build_id=sess.info.build_id,
            security_patch=sess.info.security_patch,
        ),
        signature_index=SignatureIndexMeta(
            commit=sig_meta.commit, fetched_at=sig_meta.fetched_at,
        ),
        findings=findings,
        safety_warning=_DEFAULT_SAFETY,
    )


def _collect_certs(serial: str, apps: list[InstalledApp]) -> dict[str, list[str]]:
    """For non-system apps, extract cert SHA-256 from dumpsys."""
    out: dict[str, list[str]] = {}
    for app in apps:
        if app.system:
            continue
        try:
            dump = adb.run_shell(serial, f"dumpsys package {app.package}")
        except adb.AdbError:
            continue
        hashes = cert_collector.extract_cert_sha256(dump)
        if hashes:
            out[app.package] = hashes
    return out
```

- [ ] **Step 4: Wire `scan` into `cli.py`** — add this command:

```python
@app.command()
def scan(
    serial: str | None = typer.Option(None, "--serial", help="ADB serial to target."),
    no_network: bool = typer.Option(False, "--no-network", help="Use cached signatures only."),
) -> None:
    """Run a full scan on the connected device."""
    from .reporters import console as console_reporter
    from .scan import run_scan

    report = run_scan(serial=serial, allow_network=not no_network, interactive=False)
    console_reporter.render(report, rich_console=console)
    raise typer.Exit(code=console_reporter.compute_exit_code(report))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_scan.py tests/test_cli.py -v`
Expected: all tests PASS.

- [ ] **Step 6: Smoke-test on a real device**

Run: `poetry run stalkerware-detector scan`
Expected: device panel, "Aucun finding détecté" if your phone is clean.

- [ ] **Step 7: Commit**

```bash
git add src/stalkerware_detector/scan.py src/stalkerware_detector/cli.py tests/test_scan.py
git commit -m "feat(cli): scan command wiring signatures-only pipeline"
```

**End of Phase 2 — milestone:** a clean phone returns 0 findings; an app installed under a Cerberus package name (or with matching cert) returns a CRITICAL finding.

---

## Phase 3 — Permission heuristic + side-channels

### Task 12: `collectors/permissions.py`

**Files:**
- Create: `src/stalkerware_detector/collectors/permissions.py`
- Create: `tests/test_collectors_permissions.py`

- [ ] **Step 1: Reuse `tests/fixtures/dumpsys/package_suspicious.txt` and `package_legit.txt`** (created in Task 7).

- [ ] **Step 2: Write failing tests in `tests/test_collectors_permissions.py`**

```python
from stalkerware_detector.collectors import permissions


def test_parse_runtime_permissions_grants(fixture_text):
    perms = permissions.parse_permissions(fixture_text("dumpsys/package_suspicious.txt"))
    names = {p.name for p in perms if p.granted}
    assert "android.permission.RECORD_AUDIO" in names
    assert "android.permission.ACCESS_FINE_LOCATION" in names
    assert "android.permission.READ_SMS" in names
    assert "android.permission.READ_CONTACTS" in names


def test_parse_permissions_legit_app_has_no_sensitive(fixture_text):
    perms = permissions.parse_permissions(fixture_text("dumpsys/package_legit.txt"))
    granted = {p.name for p in perms if p.granted}
    assert granted == {"android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"}


def test_collect_returns_permissions_per_package(monkeypatch, fixture_text):
    from stalkerware_detector.device import adb
    from stalkerware_detector.models import InstalledApp

    def fake_run(serial, cmd, timeout=30):
        pkg = cmd.split()[-1]
        if pkg == "com.example.spy":
            return fixture_text("dumpsys/package_suspicious.txt")
        return fixture_text("dumpsys/package_legit.txt")

    monkeypatch.setattr(adb, "run_shell", fake_run)
    apps = [
        InstalledApp(package="com.example.spy", apk_path="/data/app/x/base.apk"),
        InstalledApp(package="com.google.android.apps.maps", apk_path="/system/app/Maps.apk", system=True),
    ]
    out = permissions.collect("ABCD", apps)
    assert "com.example.spy" in out
    assert any(p.name == "android.permission.RECORD_AUDIO" for p in out["com.example.spy"])
```

- [ ] **Step 3: Write `src/stalkerware_detector/collectors/permissions.py`**

```python
"""Collect granted runtime + install permissions per package from dumpsys."""
from __future__ import annotations

import re

from ..device import adb
from ..models import GrantedPermission, InstalledApp

_PERM_LINE = re.compile(r"^\s+(?P<name>android\.permission\.[A-Z0-9_]+):\s+granted=(?P<g>true|false)")


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_collectors_permissions.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stalkerware_detector/collectors/permissions.py tests/test_collectors_permissions.py
git commit -m "feat(collectors): parse runtime+install permissions from dumpsys"
```

---

### Task 13: `collectors/device_admin.py`

**Files:**
- Create: `src/stalkerware_detector/collectors/device_admin.py`
- Create: `tests/test_collectors_device_admin.py`
- Create: `tests/fixtures/dumpsys/device_policy.txt`

- [ ] **Step 1: Write `tests/fixtures/dumpsys/device_policy.txt`**

```
Current Device Policy Manager state:
  Enabled Device Admins (User 0, provisioningState: 0):
    com.example.spy/.AdminReceiver:
      isParent=false
      uid=10456
    com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver:
      isParent=false
      uid=10987

  Owner: <none>
```

- [ ] **Step 2: Write failing tests in `tests/test_collectors_device_admin.py`**

```python
from stalkerware_detector.collectors import device_admin


def test_parse_extracts_package_names(fixture_text):
    pkgs = device_admin.parse_active(fixture_text("dumpsys/device_policy.txt"))
    assert set(pkgs) == {"com.example.spy", "com.google.android.apps.work.clouddpc"}


def test_parse_empty_when_no_admins():
    assert device_admin.parse_active("Current Device Policy Manager state:\n  Owner: <none>\n") == []
```

- [ ] **Step 3: Write `src/stalkerware_detector/collectors/device_admin.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_collectors_device_admin.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stalkerware_detector/collectors/device_admin.py tests/test_collectors_device_admin.py tests/fixtures/dumpsys/device_policy.txt
git commit -m "feat(collectors): parse active device admins"
```

---

### Task 14: `collectors/accessibility.py`

**Files:**
- Create: `src/stalkerware_detector/collectors/accessibility.py`
- Create: `tests/test_collectors_accessibility.py`
- Create: `tests/fixtures/adb/enabled_accessibility.txt`

- [ ] **Step 1: Write `tests/fixtures/adb/enabled_accessibility.txt`**

```
com.example.spy/com.example.spy.AccessibilitySvc:com.android.talkback/.TalkBackService
```

(Format from `settings get secure enabled_accessibility_services` — colon-separated, each entry is `package/service`.)

- [ ] **Step 2: Write failing tests in `tests/test_collectors_accessibility.py`**

```python
from stalkerware_detector.collectors import accessibility


def test_parse_extracts_packages(fixture_text):
    pkgs = accessibility.parse_enabled(fixture_text("adb/enabled_accessibility.txt"))
    assert set(pkgs) == {"com.example.spy", "com.android.talkback"}


def test_parse_empty_string():
    assert accessibility.parse_enabled("\n") == []
    assert accessibility.parse_enabled("null\n") == []
```

- [ ] **Step 3: Write `src/stalkerware_detector/collectors/accessibility.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_collectors_accessibility.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stalkerware_detector/collectors/accessibility.py tests/test_collectors_accessibility.py tests/fixtures/adb/enabled_accessibility.txt
git commit -m "feat(collectors): parse enabled accessibility services"
```

---

### Task 15: `signatures/legitimate_apps.yaml` — public allowlist

**Files:**
- Create: `src/stalkerware_detector/signatures/legitimate_apps.yaml`
- Modify: `src/stalkerware_detector/signatures/loader.py` (add `load_allowlist`)
- Create: `tests/test_signatures_allowlist.py`

- [ ] **Step 1: Write `src/stalkerware_detector/signatures/legitimate_apps.yaml`** — start with ~30 entries known-legitimate-but-permissive. Curate from F-Droid index and Play Store top-tier apps. Format:

```yaml
# Apps with permission profiles that would otherwise trigger HIGH but are
# legitimate, well-known software. Committed in-repo for auditability.
# An app on this list is suppressed from PermissionRiskScorer output, but
# is NOT suppressed if it matches an Echap signature (signature always wins).
apps:
  - package: com.whatsapp
    label: WhatsApp
  - package: org.thoughtcrime.securesms
    label: Signal
  - package: com.google.android.apps.maps
    label: Google Maps
  - package: com.google.android.googlequicksearchbox
    label: Google
  - package: com.google.android.gms
    label: Google Play Services
  - package: com.android.vending
    label: Play Store
  - package: org.telegram.messenger
    label: Telegram
  - package: com.facebook.orca
    label: Messenger
  - package: com.instagram.android
    label: Instagram
  - package: com.snapchat.android
    label: Snapchat
  - package: com.twitter.android
    label: X (Twitter)
  - package: com.discord
    label: Discord
  - package: com.spotify.music
    label: Spotify
  - package: com.ubercab
    label: Uber
  - package: com.zhiliaoapp.musically
    label: TikTok
  - package: org.mozilla.firefox
    label: Firefox
  - package: com.brave.browser
    label: Brave
  - package: com.android.chrome
    label: Chrome
  - package: com.microsoft.office.outlook
    label: Outlook
  - package: com.microsoft.teams
    label: Teams
  - package: com.google.android.gm
    label: Gmail
  - package: com.google.android.apps.photos
    label: Google Photos
  - package: com.lastpass.lpandroid
    label: LastPass
  - package: com.bitwarden.x8
    label: Bitwarden
  - package: org.fdroid.fdroid
    label: F-Droid
  - package: eu.faircode.email
    label: FairEmail
  - package: com.protonvpn.android
    label: ProtonVPN
  - package: ch.protonmail.android
    label: ProtonMail
  - package: com.duckduckgo.mobile.android
    label: DuckDuckGo
```

- [ ] **Step 2: Write failing test in `tests/test_signatures_allowlist.py`**

```python
from importlib.resources import files

from stalkerware_detector.signatures import loader


def test_load_allowlist_returns_set_of_packages():
    allow = loader.load_allowlist()
    assert "com.whatsapp" in allow
    assert "org.thoughtcrime.securesms" in allow
    assert "com.google.android.apps.maps" in allow
    assert len(allow) >= 25


def test_allowlist_yaml_is_packaged():
    res = files("stalkerware_detector.signatures").joinpath("legitimate_apps.yaml")
    assert res.is_file()
```

- [ ] **Step 3: Add `load_allowlist` to `src/stalkerware_detector/signatures/loader.py`**

Append to `loader.py`:

```python
from importlib.resources import files as _resource_files


def load_allowlist() -> set[str]:
    """Load the in-repo legitimate-apps allowlist (set of package names)."""
    res = _resource_files("stalkerware_detector.signatures").joinpath("legitimate_apps.yaml")
    data = yaml.safe_load(res.read_text(encoding="utf-8")) or {}
    return {str(e["package"]) for e in data.get("apps", []) if "package" in e}
```

- [ ] **Step 4: Ensure the YAML is included in the wheel** — add to `pyproject.toml` under `[tool.poetry]`:

```toml
include = [
  { path = "src/stalkerware_detector/signatures/legitimate_apps.yaml", format = ["sdist", "wheel"] },
  { path = "src/stalkerware_detector/templates/*", format = ["sdist", "wheel"] },
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `poetry run pytest tests/test_signatures_allowlist.py -v`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add src/stalkerware_detector/signatures/legitimate_apps.yaml src/stalkerware_detector/signatures/loader.py pyproject.toml tests/test_signatures_allowlist.py
git commit -m "feat(signatures): public allowlist of ~30 legitimate apps + loader"
```

---

### Task 16: `analyzers/permission_risk.py` — scoring + side-channels + allowlist

**Files:**
- Create: `src/stalkerware_detector/analyzers/permission_risk.py`
- Create: `tests/test_analyzers_permission_risk.py`

- [ ] **Step 1: Write failing tests in `tests/test_analyzers_permission_risk.py`**

```python
from stalkerware_detector.analyzers import permission_risk
from stalkerware_detector.models import (
    FindingKind,
    GrantedPermission,
    InstalledApp,
    Severity,
)


def _perms(*names: str) -> list[GrantedPermission]:
    return [GrantedPermission(name=f"android.permission.{n}", granted=True) for n in names]


def _app(pkg: str, *, system=False, installer=None) -> InstalledApp:
    return InstalledApp(
        package=pkg,
        apk_path=("/system/" if system else "/data/") + "app/x/base.apk",
        installer_package=installer,
        system=system,
    )


def test_system_apps_are_ignored():
    apps = [_app("com.android.systemui", system=True)]
    perms = {"com.android.systemui": _perms("RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS")}
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    assert findings == []


def test_high_score_with_accessibility_is_HIGH():
    apps = [_app("com.example.spy", installer=None)]
    perms = {
        "com.example.spy": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_SMS", "READ_CONTACTS",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=["com.example.spy"], allowlist=set(),
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.HIGH


def test_high_score_without_privilege_is_MEDIUM():
    apps = [_app("com.example.spy", installer="com.android.vending")]
    perms = {
        "com.example.spy": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_SMS", "READ_CONTACTS",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.MEDIUM


def test_sideloaded_with_score_3_is_MEDIUM():
    apps = [_app("com.example.spy", installer=None)]
    perms = {"com.example.spy": _perms("RECORD_AUDIO", "READ_SMS", "READ_CONTACTS")}
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist=set(),
    )
    profile = [f for f in findings if f.kind is FindingKind.PERMISSION_PROFILE]
    assert profile and profile[0].severity is Severity.MEDIUM


def test_allowlist_suppresses_permission_profile():
    apps = [_app("com.whatsapp", installer="com.android.vending")]
    perms = {
        "com.whatsapp": _perms(
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS",
            "READ_CONTACTS", "READ_CALL_LOG",
        )
    }
    findings = permission_risk.analyze(
        apps=apps, permissions=perms, device_admins=[], accessibility=[], allowlist={"com.whatsapp"},
    )
    assert all(f.kind is not FindingKind.PERMISSION_PROFILE for f in findings)


def test_device_admin_emits_HIGH_side_channel_finding():
    apps = [_app("com.example.spy", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=["com.example.spy"], accessibility=[], allowlist=set(),
    )
    da = [f for f in findings if f.kind is FindingKind.DEVICE_ADMIN]
    assert len(da) == 1
    assert da[0].severity is Severity.HIGH


def test_accessibility_emits_HIGH_side_channel_finding():
    apps = [_app("com.example.spy", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=["com.example.spy"], allowlist=set(),
    )
    acc = [f for f in findings if f.kind is FindingKind.ACCESSIBILITY_SVC]
    assert len(acc) == 1
    assert acc[0].severity is Severity.HIGH


def test_sideloaded_emits_LOW_side_channel_finding():
    apps = [_app("com.example.app", installer=None)]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=[], allowlist=set(),
    )
    side = [f for f in findings if f.kind is FindingKind.SIDELOADED_APP]
    assert len(side) == 1
    assert side[0].severity is Severity.LOW


def test_known_store_does_not_emit_sideloaded_finding():
    apps = [_app("com.example.app", installer="com.android.vending")]
    findings = permission_risk.analyze(
        apps=apps, permissions={}, device_admins=[], accessibility=[], allowlist=set(),
    )
    assert all(f.kind is not FindingKind.SIDELOADED_APP for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/test_analyzers_permission_risk.py -v`
Expected: ModuleNotFoundError on `analyzers.permission_risk`.

- [ ] **Step 3: Write `src/stalkerware_detector/analyzers/permission_risk.py`**

```python
"""Heuristic risk scoring on permission profiles + side-channel findings."""
from __future__ import annotations

import hashlib

from ..models import (
    Finding,
    FindingKind,
    GrantedPermission,
    Helpline,
    InstalledApp,
    RemediationAdvice,
    Severity,
)

SENSITIVE_PERMISSIONS: set[str] = {
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

KNOWN_STORES: set[str] = {
    "com.android.vending",            # Play Store
    "com.sec.android.app.samsungapps",  # Galaxy Store
    "com.huawei.appmarket",
    "com.amazon.venezia",
    "org.fdroid.fdroid",
    "org.fdroid.fdroid.privileged",
}

_HELP_FR = [
    Helpline(
        name="3919 — Violences faites aux femmes",
        phone="3919",
        url="https://www.solidaritefemmes.org/",
    ),
    Helpline(name="17 — Police-secours", phone="17"),
]

_SAFETY_FIRST_FR = (
    "Avant de désinstaller : la disparition du logiciel peut alerter la personne "
    "qui l'a installé. Contacter le 3919 ou la police (17) si vous êtes en danger "
    "immédiat. Conserver ce rapport comme preuve."
)


def analyze(
    *,
    apps: list[InstalledApp],
    permissions: dict[str, list[GrantedPermission]],
    device_admins: list[str],
    accessibility: list[str],
    allowlist: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    da_set = set(device_admins)
    acc_set = set(accessibility)

    for app in apps:
        if app.system:
            continue

        # Side-channel: sideloaded
        if app.installer_package not in KNOWN_STORES and app.installer_package is None:
            findings.append(_sideloaded_finding(app))

        # Side-channel: device admin / accessibility
        if app.package in da_set:
            findings.append(_admin_finding(app, kind=FindingKind.DEVICE_ADMIN))
        if app.package in acc_set:
            findings.append(_admin_finding(app, kind=FindingKind.ACCESSIBILITY_SVC))

        # Permission profile (skip if allowlisted)
        if app.package in allowlist:
            continue
        granted = {p.name for p in permissions.get(app.package, []) if p.granted}
        score = len(granted & SENSITIVE_PERMISSIONS)
        sideloaded = app.installer_package is None
        if sideloaded:
            score *= 2
        privileged = app.package in da_set or app.package in acc_set

        if score == 0:
            continue
        severity: Severity | None = None
        if score >= 5 and privileged:
            severity = Severity.HIGH
        elif score >= 5:
            severity = Severity.MEDIUM
        elif score >= 3 and sideloaded:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        findings.append(_profile_finding(app, granted, score, severity, sideloaded, privileged))

    return findings


def _profile_finding(
    app: InstalledApp,
    granted: set[str],
    score: int,
    severity: Severity,
    sideloaded: bool,
    privileged: bool,
) -> Finding:
    fid = hashlib.sha1(f"permission_profile|{app.package}".encode()).hexdigest()[:16]
    matched = sorted(granted & SENSITIVE_PERMISSIONS)
    return Finding(
        id=fid,
        severity=severity,
        kind=FindingKind.PERMISSION_PROFILE,
        target_package=app.package,
        target_label=app.label,
        summary=f"Profil de permissions sensible ({len(matched)} permissions, score={score})",
        details=(
            f"L'application **{app.package}** dispose des permissions sensibles "
            f"suivantes : " + ", ".join(p.rsplit('.', 1)[-1] for p in matched) + ". "
            f"Score brut={len(matched)}, score ajusté={score}, "
            f"sideload={sideloaded}, privilège système actif={privileged}."
        ),
        evidence={
            "matched_permissions": matched,
            "raw_score": len(matched),
            "adjusted_score": score,
            "sideloaded": sideloaded,
            "privileged": privileged,
            "installer_package": app.installer_package,
        },
        remediation=_advice(severity),
    )


def _sideloaded_finding(app: InstalledApp) -> Finding:
    fid = hashlib.sha1(f"sideloaded|{app.package}".encode()).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.LOW,
        kind=FindingKind.SIDELOADED_APP,
        target_package=app.package,
        summary="Application installée hors store officiel",
        details=(
            f"L'application **{app.package}** n'a pas été installée depuis un store "
            "connu (Play Store, Galaxy Store, F-Droid, etc.). Cela ne signifie pas "
            "qu'elle est malveillante, mais à vérifier."
        ),
        evidence={"installer_package": app.installer_package},
        remediation=RemediationAdvice(
            risk_summary="Provenance inconnue de l'application.",
            steps=["Vérifier l'origine de l'application avec son propriétaire."],
        ),
    )


def _admin_finding(app: InstalledApp, *, kind: FindingKind) -> Finding:
    label = "administrateur de l'appareil" if kind is FindingKind.DEVICE_ADMIN else "service d'accessibilité"
    fid = hashlib.sha1(f"{kind.value}|{app.package}".encode()).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.HIGH,
        kind=kind,
        target_package=app.package,
        summary=f"L'application est active comme {label}",
        details=(
            f"**{app.package}** dispose actuellement du privilège de {label}, ce "
            "qui lui permet de lire l'écran, simuler des actions, ou empêcher sa "
            "propre désinstallation. Si vous n'avez pas activé ce privilège "
            "vous-même, c'est un signal très fort."
        ),
        evidence={"privilege": kind.value},
        remediation=_advice(Severity.HIGH),
    )


def _advice(severity: Severity) -> RemediationAdvice:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return RemediationAdvice(
            risk_summary=(
                "Cette application peut accéder à des données très sensibles "
                "(micro, localisation, SMS, contacts) à votre insu."
            ),
            safety_first=_SAFETY_FIRST_FR,
            steps=[
                "Mettre ce rapport en sécurité avant toute action visible.",
                "Si privilège administrateur actif : Paramètres > Sécurité > Administrateurs.",
                "Si service d'accessibilité actif : Paramètres > Accessibilité > Services.",
                "Désinstaller depuis Paramètres > Applications.",
                "Changer les mots de passe sensibles depuis un autre appareil.",
            ],
            helplines=list(_HELP_FR),
        )
    return RemediationAdvice(
        risk_summary="Profil de permissions à examiner.",
        steps=[
            "Ouvrir Paramètres > Applications > <l'app> > Permissions.",
            "Retirer les permissions sensibles non justifiées.",
        ],
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_analyzers_permission_risk.py -v`
Expected: all 9 tests PASS.

- [ ] **Step 5: Wire the new analyzer into `scan.py`**

Edit `src/stalkerware_detector/scan.py`. Add imports:

```python
from .analyzers import permission_risk
from .collectors import accessibility as accessibility_col
from .collectors import device_admin as device_admin_col
from .collectors import permissions as permissions_col
```

Replace the body of `run_scan` after the existing `findings = signature_match.analyze(...)` line:

```python
    perms = permissions_col.collect(sess.serial, apps)
    device_admins = device_admin_col.collect(sess.serial)
    accessibility = accessibility_col.collect(sess.serial)
    allowlist = loader.load_allowlist()

    sig_findings = signature_match.analyze(apps=apps, certs_by_pkg=certs_by_pkg, index=index)
    perm_findings = permission_risk.analyze(
        apps=apps,
        permissions=perms,
        device_admins=device_admins,
        accessibility=accessibility,
        allowlist=allowlist,
    )

    # Suppress permission/side-channel findings on a package that also has a
    # signature hit, to avoid noise. The CRITICAL one is enough.
    sig_pkgs = {f.target_package for f in sig_findings}
    perm_findings = [f for f in perm_findings if f.target_package not in sig_pkgs]

    findings = sig_findings + perm_findings
```

- [ ] **Step 6: Update `tests/test_scan.py` to also exercise the new analyzer**

Add a test:

```python
def test_run_scan_emits_permission_profile(monkeypatch, fixtures_dir):
    sess = _make_session()
    apps = [
        InstalledApp(
            package="com.example.spy", apk_path="/data/app/x/base.apk",
            installer_package=None, system=False,
        )
    ]
    monkeypatch.setattr(scan.session, "connect", lambda **kw: sess)
    monkeypatch.setattr(scan.packages, "collect", lambda serial: apps)
    monkeypatch.setattr(scan, "_collect_certs", lambda serial, apps: {})
    monkeypatch.setattr(scan.permissions_col, "collect", lambda serial, apps: {
        "com.example.spy": [
            scan.permission_risk.GrantedPermission(name=f"android.permission.{n}")
            for n in ("RECORD_AUDIO", "READ_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_CALL_LOG")
        ]
    })
    monkeypatch.setattr(scan.device_admin_col, "collect", lambda serial: [])
    monkeypatch.setattr(scan.accessibility_col, "collect", lambda serial: [])
    monkeypatch.setattr(
        scan.fetcher, "ensure_fresh",
        lambda target, allow_network, force=False: IndexMeta(fetched_at=1.0, commit="abc"),
    )
    monkeypatch.setattr(scan.fetcher, "default_cache_dir", lambda: fixtures_dir / "echap_mini")

    report = scan.run_scan(serial=None, allow_network=True, interactive=False)
    kinds = {f.kind for f in report.findings}
    assert FindingKind.PERMISSION_PROFILE in kinds or FindingKind.SIDELOADED_APP in kinds
```

Note: import `GrantedPermission` directly in the test to avoid the indirection:
```python
from stalkerware_detector.models import FindingKind, GrantedPermission, InstalledApp
```
and replace `scan.permission_risk.GrantedPermission(...)` with `GrantedPermission(...)`.

- [ ] **Step 7: Run all tests**

Run: `poetry run pytest -q`
Expected: full suite PASS.

- [ ] **Step 8: Smoke-test on a real device**

Run: `poetry run stalkerware-detector scan`
Expected: clean phone = 0 finding HIGH/CRITICAL. Sideloaded apps (if any) appear as LOW.

- [ ] **Step 9: Commit**

```bash
git add src/stalkerware_detector/analyzers/permission_risk.py src/stalkerware_detector/scan.py tests/test_analyzers_permission_risk.py tests/test_scan.py
git commit -m "feat(analyzers): permission risk scoring + side-channels wired in scan"
```

**End of Phase 3 — milestone:** a clean phone produces 0 finding HIGH/CRITICAL. A sideloaded app with 3+ sensitive permissions produces MEDIUM. With accessibility/device admin active, HIGH.

> **Note on remediation catalog:** the spec mentions `remediation/advisor.py`. We've kept the advice text co-located with each analyzer in Phase 2/3, which is fine for v1 (small catalog, single language). When EN translations are added later, extracting an `advisor.py` is a justified refactor — but introducing it now would be premature abstraction.

---

## Phase 4 — JSON + HTML reporters and optional APK hashing

### Task 17: `reporters/json_report.py`

**Files:**
- Create: `src/stalkerware_detector/reporters/json_report.py`
- Create: `tests/test_reporters_json.py`
- Create: `tests/__snapshots__/.gitkeep` (syrupy stores snapshots here)

- [ ] **Step 1: Write failing tests in `tests/test_reporters_json.py`**

```python
import json
from datetime import datetime
from pathlib import Path

from stalkerware_detector.models import (
    DeviceInfo,
    Finding,
    FindingKind,
    Helpline,
    RemediationAdvice,
    ScanReport,
    Severity,
    SignatureIndexMeta,
)
from stalkerware_detector.reporters import json_report


def _sample_report():
    return ScanReport(
        generated_at=datetime(2026, 5, 13, 12, 0, 0),
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33,
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=[
            Finding(
                id="f1",
                severity=Severity.CRITICAL,
                kind=FindingKind.SIGNATURE_HIT,
                target_package="com.lsdroid.cerberus",
                summary="Stalkerware connu : cerberus",
                details="...",
                evidence={"matched_on": "package"},
                remediation=RemediationAdvice(
                    risk_summary="risk",
                    safety_first="warn",
                    steps=["s1"],
                    helplines=[Helpline(name="3919", phone="3919")],
                ),
            ),
        ],
        safety_warning="warn",
    )


def test_write_creates_valid_json(tmp_path: Path):
    out = tmp_path / "scan.json"
    json_report.write(_sample_report(), out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["device"]["model"] == "Pixel 7"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["evidence"]["matched_on"] == "package"
    assert payload["summary"]["critical"] == 1


def test_to_dict_is_stable_snapshot(snapshot):
    payload = json_report.to_dict(_sample_report())
    assert payload == snapshot
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/test_reporters_json.py -v`
Expected: ModuleNotFoundError on `json_report`.

- [ ] **Step 3: Write `src/stalkerware_detector/reporters/json_report.py`**

```python
"""JSON report writer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ScanReport


def to_dict(report: ScanReport) -> dict[str, Any]:
    """Return a stable, JSON-serializable dict for the report."""
    return report.model_dump(mode="json")


def write(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")
```

- [ ] **Step 4: Update tests/test_reporters_json.py** — when snapshot doesn't exist yet, run:

Run: `poetry run pytest tests/test_reporters_json.py --snapshot-update -v`
Then run again: `poetry run pytest tests/test_reporters_json.py -v`
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/stalkerware_detector/reporters/json_report.py tests/test_reporters_json.py tests/__snapshots__
git commit -m "feat(reporters): JSON writer with model_dump + snapshot test"
```

---

### Task 18: `reporters/html_report.py` — Jinja2, inline CSS, no external JS

**Files:**
- Create: `src/stalkerware_detector/templates/report.html.j2`
- Create: `src/stalkerware_detector/reporters/html_report.py`
- Create: `tests/test_reporters_html.py`

- [ ] **Step 1: Write `src/stalkerware_detector/templates/report.html.j2`**

```html
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="stalkerware-detector {{ report.tool_version }}">
<title>Rapport de scan — {{ report.device.model or 'téléphone' }}</title>
<style>
  :root { color-scheme: light; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; padding: 1.5rem; background:#f7f7f8; color:#1d1d1f; }
  main { max-width: 880px; margin: 0 auto; }
  h1 { margin: 0 0 0.5rem 0; font-size: 1.6rem; }
  h2 { font-size: 1.2rem; margin-top: 2rem; }
  .meta { color:#555; font-size: 0.9rem; }
  .safety { background:#b91c1c; color:white; padding:1rem 1.25rem; border-radius:8px;
            margin: 1.5rem 0; font-weight: 600; }
  .summary { display:flex; gap:0.5rem; flex-wrap:wrap; margin:1rem 0; }
  .pill { padding:0.25rem 0.65rem; border-radius:999px; font-size:0.85rem;
          font-weight:600; color:white; }
  .pill.critical { background:#7f1d1d; }
  .pill.high     { background:#b91c1c; }
  .pill.medium   { background:#b45309; }
  .pill.low      { background:#1d4ed8; }
  .pill.info     { background:#52525b; }
  .finding { background:white; border-radius:8px; padding:1rem 1.25rem;
             margin-bottom:0.75rem; border-left:6px solid #ddd; }
  .finding.critical { border-left-color:#7f1d1d; }
  .finding.high     { border-left-color:#b91c1c; }
  .finding.medium   { border-left-color:#b45309; }
  .finding.low      { border-left-color:#1d4ed8; }
  .finding h3 { margin:0 0 0.25rem 0; font-size: 1.05rem; }
  .finding .pkg { color:#555; font-family: ui-monospace, monospace; font-size:0.9rem; }
  .finding ul { margin: 0.5rem 0 0 1rem; }
  .help { background:#eef2ff; padding:0.75rem 1rem; border-radius:6px; margin-top:1rem;
          font-size:0.95rem; }
  footer { color:#777; font-size:0.8rem; margin-top:2.5rem; text-align:center; }
  code { background:#eee; padding:0.05rem 0.3rem; border-radius:4px; }
</style>
</head>
<body>
<main>
  <h1>Rapport de scan</h1>
  <div class="meta">
    Généré le {{ report.generated_at.strftime('%Y-%m-%d %H:%M') }}
    par stalkerware-detector {{ report.tool_version }} —
    {{ report.device.manufacturer }} {{ report.device.model }}
    (Android {{ report.device.android_release }}, patch {{ report.device.security_patch or '—' }})
  </div>

  {% if has_severe %}
  <div class="safety">⚠ {{ report.safety_warning }}</div>
  {% endif %}

  <h2>Résumé</h2>
  <div class="summary">
    {% for sev in ('critical','high','medium','low','info') %}
      <span class="pill {{ sev }}">{{ sev.upper() }} : {{ report.summary.get(sev, 0) }}</span>
    {% endfor %}
  </div>

  {% if report.findings %}
  <h2>Findings ({{ report.findings | length }})</h2>
  {% for f in findings_sorted %}
    <article class="finding {{ f.severity.value }}">
      <h3>{{ f.summary }}</h3>
      <div class="pkg">{{ f.target_package }} — <em>{{ f.kind.value }}</em></div>
      <p>{{ f.details }}</p>
      {% if f.remediation.safety_first %}
        <div class="safety">⚠ {{ f.remediation.safety_first }}</div>
      {% endif %}
      {% if f.remediation.steps %}
        <strong>À faire :</strong>
        <ul>{% for s in f.remediation.steps %}<li>{{ s }}</li>{% endfor %}</ul>
      {% endif %}
      {% if f.remediation.helplines %}
        <div class="help">
          <strong>Aide :</strong>
          <ul>{% for h in f.remediation.helplines %}
            <li>{{ h.name }}{% if h.phone %} — <code>{{ h.phone }}</code>{% endif %}
              {% if h.url %} — <a href="{{ h.url }}">{{ h.url }}</a>{% endif %}</li>
          {% endfor %}</ul>
        </div>
      {% endif %}
    </article>
  {% endfor %}
  {% else %}
    <p><strong>Aucun finding détecté.</strong></p>
  {% endif %}

  <footer>
    Index signatures : <code>{{ report.signature_index.commit }}</code> —
    Schéma rapport : v{{ report.schema_version }}
  </footer>
</main>
</body>
</html>
```

- [ ] **Step 2: Write failing tests in `tests/test_reporters_html.py`**

```python
from datetime import datetime
from pathlib import Path

from stalkerware_detector.models import (
    DeviceInfo,
    Finding,
    FindingKind,
    Helpline,
    RemediationAdvice,
    ScanReport,
    Severity,
    SignatureIndexMeta,
)
from stalkerware_detector.reporters import html_report


def _critical_finding():
    return Finding(
        id="f1",
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package="com.lsdroid.cerberus",
        summary="Stalkerware connu : cerberus",
        details="détails.",
        evidence={},
        remediation=RemediationAdvice(
            risk_summary="risk",
            safety_first="be careful",
            steps=["s1", "s2"],
            helplines=[Helpline(name="3919", phone="3919")],
        ),
    )


def _report(findings):
    return ScanReport(
        generated_at=datetime(2026, 5, 13, 12, 0, 0),
        tool_version="0.1.0",
        device=DeviceInfo(
            serial_redacted="****EFGH", manufacturer="Google", model="Pixel 7",
            android_release="13", sdk_int=33, security_patch="2026-04",
        ),
        signature_index=SignatureIndexMeta(commit="abc1234", fetched_at=1700000000.0),
        findings=findings,
        safety_warning="warn",
    )


def test_render_html_contains_critical_finding_and_safety_banner():
    html = html_report.render_html(_report([_critical_finding()]))
    assert "Stalkerware connu" in html
    assert "com.lsdroid.cerberus" in html
    assert "be careful" in html
    assert 'class="safety"' in html


def test_render_html_no_safety_banner_when_no_severe_findings():
    html = html_report.render_html(_report([]))
    assert "Aucun finding" in html
    # Safety banner should NOT appear at top level if no high/critical
    assert html.count('class="safety"') == 0


def test_render_html_has_no_external_resources():
    html = html_report.render_html(_report([_critical_finding()]))
    assert "<script" not in html.lower()
    assert "http://" not in html  # but allow https for safety links
    # Allowed https URLs only inside helpline section
    for line in html.splitlines():
        if "src=" in line:
            assert False, f"External resource referenced: {line}"


def test_write_creates_file(tmp_path: Path):
    out = tmp_path / "report.html"
    html_report.write(_report([_critical_finding()]), out)
    assert out.exists()
    assert "Stalkerware connu" in out.read_text(encoding="utf-8")
```

- [ ] **Step 3: Write `src/stalkerware_detector/reporters/html_report.py`**

```python
"""HTML report writer (Jinja2 + inline CSS, no external resources)."""
from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape

from ..models import ScanReport, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_html(report: ScanReport) -> str:
    template_src = (
        files("stalkerware_detector.templates")
        .joinpath("report.html.j2")
        .read_text(encoding="utf-8")
    )
    env = Environment(autoescape=select_autoescape(["html"]))
    template = env.from_string(template_src)
    has_severe = any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in report.findings)
    findings_sorted = sorted(report.findings, key=lambda f: (_ORDER.index(f.severity), f.target_package))
    return template.render(report=report, has_severe=has_severe, findings_sorted=findings_sorted)


def write(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `poetry run pytest tests/test_reporters_html.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 5: Wire JSON + HTML into the CLI**

Edit the `scan` command in `cli.py`:

```python
@app.command()
def scan(
    serial: str | None = typer.Option(None, "--serial"),
    no_network: bool = typer.Option(False, "--no-network"),
    output: Path = typer.Option(Path("./reports"), "--output"),
    with_apk_hash: bool = typer.Option(False, "--with-apk-hash"),
) -> None:
    """Run a full scan on the connected device."""
    from datetime import datetime
    from pathlib import Path as _Path
    from .reporters import console as console_reporter
    from .reporters import html_report, json_report
    from .scan import run_scan

    report = run_scan(
        serial=serial, allow_network=not no_network,
        interactive=False, with_apk_hash=with_apk_hash,
    )
    console_reporter.render(report, rich_console=console)

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    output.mkdir(parents=True, exist_ok=True)
    json_report.write(report, output / f"scan-{ts}.json")
    html_report.write(report, output / f"scan-{ts}.html")
    console.print(f"[green]rapport JSON[/green] : {output / f'scan-{ts}.json'}")
    console.print(f"[green]rapport HTML[/green] : {output / f'scan-{ts}.html'}")

    raise typer.Exit(code=console_reporter.compute_exit_code(report))
```

(Note: `with_apk_hash` parameter is added now; the implementation lands in Task 19. `run_scan` must accept it now and ignore it for the moment.)

Add a parameter to `run_scan` in `scan.py`:

```python
def run_scan(*, serial, allow_network, interactive, with_apk_hash: bool = False):
    # ... existing body unchanged for now; with_apk_hash will be honored in Task 19
```

- [ ] **Step 6: Run all tests**

Run: `poetry run pytest -q`
Expected: full suite PASS.

- [ ] **Step 7: Commit**

```bash
git add src/stalkerware_detector/templates src/stalkerware_detector/reporters/html_report.py src/stalkerware_detector/cli.py src/stalkerware_detector/scan.py tests/test_reporters_html.py
git commit -m "feat(reporters): HTML output with inline CSS + safety banner; wire all three outputs into scan"
```

---

### Task 19: Optional APK hashing (`--with-apk-hash`)

Extend signature matching to detect *renamed* stalkerware by hashing the APK file when neither the package name nor cert matches. Disabled by default because `adb pull` may trigger a persistent notification on the phone.

**Files:**
- Modify: `src/stalkerware_detector/analyzers/signature_match.py`
- Modify: `src/stalkerware_detector/scan.py`
- Create: `src/stalkerware_detector/collectors/apk_hash.py`
- Create: `tests/test_collectors_apk_hash.py`
- Modify: `tests/test_analyzers_signature_match.py`

- [ ] **Step 1: Write failing tests in `tests/test_collectors_apk_hash.py`**

```python
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
        InstalledApp(package="com.android.systemui", apk_path="/system/app/SystemUI.apk", system=True),
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
```

- [ ] **Step 2: Write `src/stalkerware_detector/collectors/apk_hash.py`**

```python
"""Compute SHA-256 of APKs by pulling them via adb (optional, off by default)."""
from __future__ import annotations

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
            try:
                local.unlink()
            except FileNotFoundError:
                pass
    return out
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `poetry run pytest tests/test_collectors_apk_hash.py -v`
Expected: 3 PASS.

- [ ] **Step 4: Extend `analyzers/signature_match.py`** to accept apk hashes

Modify the `analyze` signature:

```python
def analyze(
    *,
    apps: list[InstalledApp],
    certs_by_pkg: dict[str, list[str]],
    apk_hashes_by_pkg: dict[str, str] | None = None,
    index: IOCIndex,
) -> list[Finding]:
    """Return findings for apps matching a known stalkerware IOC.

    Match order: package > cert > apk_sha256 (apk hash only when others fail).
    """
    apk_hashes_by_pkg = apk_hashes_by_pkg or {}
    findings: list[Finding] = []
    for app in apps:
        ioc = index.match_package(app.package)
        matched_on = "package"
        matched_value: str = app.package

        if ioc is None:
            for cert in certs_by_pkg.get(app.package, []):
                hit = index.match_cert(cert)
                if hit is not None:
                    ioc, matched_on, matched_value = hit, "cert", cert
                    break

        if ioc is None:
            sha = apk_hashes_by_pkg.get(app.package)
            if sha:
                hit = index.match_apk_sha256(sha)
                if hit is not None:
                    ioc, matched_on, matched_value = hit, "apk_sha256", sha

        if ioc is None:
            continue
        findings.append(_build_finding(app, ioc, matched_on, matched_value))
    return findings
```

Add a test in `tests/test_analyzers_signature_match.py`:

```python
def test_match_by_apk_sha256_when_package_and_cert_unknown(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    apps = [
        InstalledApp(package="com.renamed.x", apk_path="/data/app/x/base.apk")
    ]
    apk_hashes = {"com.renamed.x": "1" * 64}
    findings = signature_match.analyze(
        apps=apps, certs_by_pkg={}, apk_hashes_by_pkg=apk_hashes, index=index,
    )
    assert len(findings) == 1
    assert findings[0].evidence["matched_on"] == "apk_sha256"
```

- [ ] **Step 5: Wire into `scan.py`**

```python
def run_scan(*, serial, allow_network, interactive, with_apk_hash: bool = False):
    sess = session.connect(requested_serial=serial, interactive=interactive)
    cache_dir = fetcher.default_cache_dir()
    sig_meta = fetcher.ensure_fresh(cache_dir, allow_network=allow_network)
    index = loader.load_index(cache_dir)

    apps = packages.collect(sess.serial)
    certs_by_pkg = _collect_certs(sess.serial, apps)

    apk_hashes_by_pkg: dict[str, str] = {}
    if with_apk_hash:
        import tempfile
        from .collectors import apk_hash
        with tempfile.TemporaryDirectory(prefix="stkwd-") as td:
            apk_hashes_by_pkg = apk_hash.collect(sess.serial, apps, tmp_dir=Path(td))

    perms = permissions_col.collect(sess.serial, apps)
    device_admins = device_admin_col.collect(sess.serial)
    accessibility = accessibility_col.collect(sess.serial)
    allowlist = loader.load_allowlist()

    sig_findings = signature_match.analyze(
        apps=apps, certs_by_pkg=certs_by_pkg,
        apk_hashes_by_pkg=apk_hashes_by_pkg, index=index,
    )
    perm_findings = permission_risk.analyze(
        apps=apps, permissions=perms,
        device_admins=device_admins, accessibility=accessibility,
        allowlist=allowlist,
    )
    sig_pkgs = {f.target_package for f in sig_findings}
    perm_findings = [f for f in perm_findings if f.target_package not in sig_pkgs]

    return ScanReport(
        tool_version=__version__,
        device=DeviceInfo(
            serial_redacted=session.redact_serial(sess.serial),
            manufacturer=sess.info.manufacturer,
            model=sess.info.model,
            android_release=sess.info.android_release,
            sdk_int=sess.info.sdk_int,
            build_id=sess.info.build_id,
            security_patch=sess.info.security_patch,
        ),
        signature_index=SignatureIndexMeta(commit=sig_meta.commit, fetched_at=sig_meta.fetched_at),
        findings=sig_findings + perm_findings,
        safety_warning=_DEFAULT_SAFETY,
    )
```

Add the `pathlib.Path` import at the top of `scan.py` if not present.

- [ ] **Step 6: Run full test suite**

Run: `poetry run pytest -q`
Expected: full suite PASS (~50 tests).

- [ ] **Step 7: Commit**

```bash
git add src/stalkerware_detector/collectors/apk_hash.py src/stalkerware_detector/analyzers/signature_match.py src/stalkerware_detector/scan.py tests/test_collectors_apk_hash.py tests/test_analyzers_signature_match.py
git commit -m "feat(analyzers): optional APK SHA-256 matching via --with-apk-hash"
```

---

### Task 20: README, FAQ, gitignored reports, final polish

**Files:**
- Modify: `README.md`
- Modify: `.gitignore`
- Modify: `src/stalkerware_detector/cli.py` (final --verbose flag)

- [ ] **Step 1: Update `.gitignore`** — add a line for `reports/` (already gitignored from initial commit; verify).

- [ ] **Step 2: Write the full `README.md`**

Replace the placeholder README with:

````markdown
# stalkerware-detector

Scan an Android phone connected via USB to detect installed stalkerware. Uses the
Coalition Against Stalkerware (Echap) signature database, plus a permission
heuristic to flag suspect apps the signature DB doesn't know yet.

**Status:** v0.1 — French CLI/HTML output. Detection logic is signature + permission
profile only (no network capture, no iOS, no full forensic).

## Who this is for

Journalists, security responders, IT-savvy folks helping a friend or relative.
The HTML report is written so it can be shared with a victim who is not technical.

## Prerequisites

- Python 3.11+
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
  (provides `adb`) — must be on your PATH
- The phone must have **USB debugging enabled** (Settings > About > tap "Build
  number" 7 times to unlock Developer options, then Developer options > USB debugging)
- The user must accept the RSA fingerprint prompt on the phone

## Install

```bash
poetry install
poetry run stalkerware-detector doctor
```

`doctor` verifies your setup: that `adb` is on PATH, that a device is connected
and authorized, and that the OS metadata can be read.

## Usage

```bash
# Run a full scan with default options
poetry run stalkerware-detector scan

# Specify a target device when several are connected
poetry run stalkerware-detector scan --serial ABCD1234EFGH

# Pull and hash every non-store APK (slower, may trigger ADB notification on phone)
poetry run stalkerware-detector scan --with-apk-hash

# Refresh the Echap signature database now (otherwise refreshed every 24h)
poetry run stalkerware-detector update-sigs
```

Reports land in `./reports/scan-<timestamp>.{json,html}` and are also printed to
the terminal.

## Exit codes

| Code | Meaning |
|---|---|
| 0  | No finding |
| 1  | LOW/MEDIUM findings only |
| 2  | At least one HIGH finding |
| 3  | At least one CRITICAL finding |
| 10 | `adb` missing |
| 11 | No device connected |
| 12 | Device unauthorized |
| 13 | Device offline |
| 14 | Multiple devices, no `--serial` provided |
| 20 | Network unreachable and no signature cache |
| 21 | Signature cache corrupted |

## Safety

- The tool emits no telemetry. It contacts only (a) the public Echap GitHub repo
  for signature updates and (b) your local `adb`. Inspect the source to verify.
- HTML reports contain zero external resources (no script, no remote CSS/images).
- We never pull user data from `/data/data/<pkg>/`; only `base.apk` files when
  `--with-apk-hash` is set.
- Device serials are redacted to the last 4 characters in reports.

## FAQ

**Why not just use MVT?**
MVT (Amnesty's Mobile Verification Toolkit) is a full forensic suite. We focus
narrowly on stalkerware detection with a victim-friendly HTML output.

**Why not TinyCheck?**
TinyCheck analyses network traffic via Wi-Fi. We complement it with a device-side
scan over USB.

**What if I'm in danger right now?**
Stop, do not uninstall anything visible to the suspected installer. Call:
- France — **3919** (free, anonymous, violence against women hotline)
- France — **17** (police, in immediate danger)

## License

GPL-3.0-or-later. See LICENSE.
````

- [ ] **Step 3: Add a `--verbose` global option to `cli.py`** for parity with the spec

At the top of `cli.py`, replace the app definition with:

```python
app = typer.Typer(no_args_is_help=True, add_completion=False)

@app.callback()
def _global(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    import logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
```

- [ ] **Step 4: Run full test suite & ruff**

Run: `poetry run pytest -q && poetry run ruff check .`
Expected: all green.

- [ ] **Step 5: End-to-end smoke test on a real device**

Run: `poetry run stalkerware-detector scan`
Expected:
- Console shows device panel, summary, "Aucun finding détecté" (clean phone) or finding table.
- Two files appear under `./reports/scan-<timestamp>.{json,html}`.
- Opening the HTML in a browser shows the same content.

- [ ] **Step 6: Commit**

```bash
git add README.md src/stalkerware_detector/cli.py
git commit -m "docs(readme): full v0.1 README; chore(cli): global --verbose flag"
```

- [ ] **Step 7: Tag the release**

```bash
git tag -a v0.1.0 -m "v0.1.0 — signature + permission detection, FR remediation"
```

(Don't push — the user decides when to push to GitHub.)

---

## Final verification checklist

After Task 20, run this final pass:

- [ ] `poetry run pytest -q` — full suite green
- [ ] `poetry run ruff check .` — no warnings
- [ ] `poetry run stalkerware-detector doctor` — on a real device, prints the device info
- [ ] `poetry run stalkerware-detector update-sigs` — refreshes the cache
- [ ] `poetry run stalkerware-detector scan` — emits report files, console output
- [ ] HTML report opens correctly in a browser, no broken layout, no external resources
- [ ] JSON schema_version == "1.0"
- [ ] On a clean phone: 0 finding HIGH/CRITICAL
- [ ] If you have a test stalkerware (sideloaded under an Echap-known package): CRITICAL finding appears

---

## Out of scope (deferred to later releases)

These were excluded in the spec and intentionally not included as tasks:

- Network traffic capture (TinyCheck territory)
- iOS scanning (MVT-iOS territory)
- Log/backup `.ab` analysis (full forensics)
- GUI wrapper
- Manually installed CA certificate detection (network interception)
- Automated stalkerware uninstall (ethical: the victim decides)
- English / multilingual remediation copy
- PyPI publication
