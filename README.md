# Stalkerware Detector

Scanner ADB pour la détection de stalkerware sur Android. v1 en cours de spec.

## Prerequisites

- Python 3.11 or 3.12
- [Poetry](https://python-poetry.org/) for dependency management
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools) — `adb` must be on your `PATH`
- An Android phone with USB debugging enabled, connected over USB

## Installation

```bash
poetry install
```

This creates a virtualenv and installs the runtime + dev dependencies.

## Quick start

```bash
poetry run stalkerware-detector --help
```

(Subcommands are added in subsequent tasks.)

## Development

```bash
poetry run pytest -q
poetry run ruff check .
```
