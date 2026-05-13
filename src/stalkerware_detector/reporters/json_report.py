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
