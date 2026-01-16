from __future__ import annotations

import typer

from argus import __version__, paths

app = typer.Typer(add_completion=False, invoke_without_command=True)


def set_state(value: str) -> None:
    paths.ensure_dirs()
    paths.state_file().write_text(value.strip() + "\n", encoding="utf-8")


def get_state() -> str:
    try:
        return paths.state_file().read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "STOPPED"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Mostra versione ed esce"),
):
    # Preparazione: crea cartelle standard (~/.config/argus, ~/.local/share/argus, reports/)
    paths.ensure_dirs()

    # Crea config.yaml al primo avvio (Milestone 1b)
    from argus.config import ensure_config_exists
    ensure_config_exists()

    if version:
        typer.echo(f"argus {__version__}")
        raise typer.Exit()

    # Se l'utente scrive solo `argus`, apriamo la TUI
    if ctx.invoked_subcommand is None:
        from argus.tui import ArgusApp
        ArgusApp().run()
        raise typer.Exit()


@app.command()
def status():
    """Mostra lo stato (RUNNING/STOPPED)."""
    typer.echo(get_state())


@app.command()
def start():
    """Avvia (placeholder v1)."""
    set_state("RUNNING")
    typer.echo("RUNNING")


@app.command()
def stop():
    """Ferma (placeholder v1)."""
    set_state("STOPPED")
    typer.echo("STOPPED")
