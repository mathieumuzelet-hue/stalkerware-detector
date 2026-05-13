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
    findings_sorted = sorted(
        report.findings, key=lambda f: (_ORDER.index(f.severity), f.target_package)
    )
    return template.render(report=report, has_severe=has_severe, findings_sorted=findings_sorted)


def write(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
