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
    candidates = (
        list(samples_dir.glob("*.yaml"))
        if samples_dir.exists()
        else list(root.glob("**/*.yaml"))
    )
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
    return index
