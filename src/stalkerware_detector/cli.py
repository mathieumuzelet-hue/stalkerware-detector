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


@app.command("update-sigs")
def update_sigs(
    force: bool = typer.Option(True, help="Ignore the 24h cache and refresh now."),
) -> None:
    """Fetch the latest Echap signature index."""
    from .signatures import fetcher

    target = fetcher.default_cache_dir()
    meta = fetcher.ensure_fresh(target, allow_network=True, force=force)
    console.print(f"[green]signature index[/green] : {target}")
    console.print(f"commit : {meta.commit}")


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
