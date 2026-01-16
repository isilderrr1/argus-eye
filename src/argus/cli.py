from __future__ import annotations

from pathlib import Path
import typer

from argus import __version__

app = typer.Typer(add_completion=False)

# Percorsi (v1 semplice): in seguito li centralizziamo in un modulo "paths.py"
STATE_DIR = Path.home() / ".local" / "share" / "argus"
STATE_FILE = STATE_DIR / "state.txt"


def ensure_state_dir() -> None:
    """Crea la cartella di stato se non esiste."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def set_state(value: str) -> None:
    """Salva lo stato (RUNNING/STOPPED)."""
    ensure_state_dir()
    STATE_FILE.write_text(value.strip() + "\n", encoding="utf-8")


def get_state() -> str:
    """Legge lo stato, default STOPPED."""
    try:
        return STATE_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "STOPPED"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Mostra versione ed esce"),
):
    if version:
        typer.echo(f"argus {__version__}")
        raise typer.Exit()

    # Se l'utente scrive solo `argus` (nessun comando), apriamo la TUI
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
