"""Load YAML signature samples (Echap format) into a fast lookup index.

The real Echap repository (AssoEchap/stalkerware-indicators) ships two top-level
YAML files at its root:

  - ``ioc.yaml``       (stalkerware entries)
  - ``watchware.yaml`` (parental-control / watchware entries)

Each file is a YAML LIST. Each entry is a dict with this shape::

    - name: TheTruthSpy
      names: [Copy9, InoSPy, ...]               # optional aliases (ignored)
      type: stalkerware                          # or "watchware"
      packages: [com.apspy.app, com.fone, ...]
      certificates:                              # SHA-1 hex, 40 chars
        - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
      sha256:                                    # optional APK SHA-256, 64 chars
        - aabbcc...
      references: [...]                          # optional
      websites: [...]                            # optional, ignored
      c2: {...}                                  # optional, ignored

For backward compatibility with the in-repo test fixtures we fall back to the
legacy ``samples/*.yaml`` format (dict with ``apps`` key) when neither
``ioc.yaml`` nor ``watchware.yaml`` is present.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib.resources import files as _resource_files
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
    """Build an IOCIndex from the Echap cache at ``root``.

    Tries the real top-level ``ioc.yaml`` / ``watchware.yaml`` files first.
    Falls back to the legacy ``samples/*.yaml`` layout if neither exists (used
    by the in-repo test fixtures).
    """
    index = IOCIndex()

    real_files = [
        root / "ioc.yaml",
        root / "watchware.yaml",
    ]
    real_present = [p for p in real_files if p.exists()]
    if real_present:
        for yaml_path in real_present:
            _load_real_format(yaml_path, index)
        return index

    # --- legacy fallback ---------------------------------------------------
    samples_dir = root / "samples"
    if not samples_dir.exists():
        log.warning(
            "No signature files found at %s "
            "(expected ioc.yaml/watchware.yaml or samples/*.yaml)",
            root,
        )
        return index
    for yaml_path in samples_dir.glob("*.yaml"):
        _load_legacy_format(yaml_path, index)
    return index


def _load_real_format(yaml_path: Path, index: IOCIndex) -> None:
    """Parse one top-level Echap YAML file (a list of entries)."""
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        log.warning("Failed to parse %s: %s", yaml_path, e)
        return
    if not isinstance(data, list):
        log.warning("Skipping %s: top-level is not a YAML list", yaml_path)
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not name:
            continue
        sample_type = str(entry.get("type") or "stalkerware")
        packages = entry.get("packages") or []
        certificates = tuple(
            str(c).lower() for c in (entry.get("certificates") or [])
        )
        apk_hashes = tuple(
            str(h).lower() for h in (entry.get("sha256") or [])
        )
        references = tuple(str(r) for r in (entry.get("references") or []))
        for package in packages:
            if not package:
                continue
            ioc = SampleIOC(
                name=str(name),
                type=sample_type,
                package=str(package),
                certificates=certificates,
                apk_hashes=apk_hashes,
                references=references,
                source_path=str(yaml_path),
            )
            index.by_package[ioc.package] = ioc
            for cert in certificates:
                index.by_cert[cert] = ioc
            for sha in apk_hashes:
                index.by_sha256[sha] = ioc


def _load_legacy_format(yaml_path: Path, index: IOCIndex) -> None:
    """Parse one legacy ``samples/<vendor>.yaml`` file (dict with ``apps``)."""
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        log.warning("Failed to parse %s: %s", yaml_path, e)
        return
    if not isinstance(data, dict) or "apps" not in data:
        log.warning("Skipping %s: no 'apps' key", yaml_path)
        return
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
            certificates=tuple(
                str(c).lower() for c in app.get("certificates", []) or []
            ),
            apk_hashes=tuple(
                str(h).lower() for h in app.get("sha256", []) or []
            ),
            references=references,
            source_path=str(yaml_path),
        )
        index.by_package[ioc.package] = ioc
        for cert in ioc.certificates:
            index.by_cert[cert] = ioc
        for sha in ioc.apk_hashes:
            index.by_sha256[sha] = ioc


def load_allowlist() -> set[str]:
    """Load the in-repo legitimate-apps allowlist (set of package names)."""
    res = _resource_files("stalkerware_detector.signatures").joinpath("legitimate_apps.yaml")
    data = yaml.safe_load(res.read_text(encoding="utf-8")) or {}
    return {str(e["package"]) for e in data.get("apps", []) if "package" in e}
