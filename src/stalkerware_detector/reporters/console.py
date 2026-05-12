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
