from __future__ import annotations

import typer

from argus import __version__, paths, db

app = typer.Typer(add_completion=False, invoke_without_command=True)


def parse_duration(s: str) -> int:
    """
    Accetta: 10m, 30m, 1h, 2h
    Ritorna secondi.
    """
    s = s.strip().lower()
    if s.endswith("m") and s[:-1].isdigit():
        return int(s[:-1]) * 60
    if s.endswith("h") and s[:-1].isdigit():
        return int(s[:-1]) * 3600
    raise typer.BadParameter("Durata non valida. Usa formato tipo 10m o 1h.")


def fmt_seconds(sec: int) -> str:
    """Formatta secondi in modo leggibile (es. 9m12s / 1h05m)."""
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def set_state(value: str) -> None:
    # stato del monitor nel DB (niente scadenza)
    db.set_flag("monitor_state", value, ttl_seconds=None)


def get_state() -> str:
    data = db.get_flag("monitor_state")
    if data is None:
        return "STOPPED"
    return data[0]


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Mostra versione ed esce"),
):
    # Preparazione ambiente (cartelle standard)
    paths.ensure_dirs()

    # Inizializza DB (crea tabelle se mancano)
    db.init_db()

    # Crea config.yaml al primo avvio
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
    """Mostra lo stato (RUNNING/STOPPED) + flag runtime."""
    state = get_state()

    mute_left = db.remaining_seconds("mute")
    maint_left = db.remaining_seconds("maintenance")

    typer.echo(f"STATE: {state}")
    if mute_left is None:
        typer.echo("MUTE: OFF")
    else:
        typer.echo(f"MUTE: ON ({fmt_seconds(mute_left)} rimanenti)")

    if maint_left is None:
        typer.echo("MAINTENANCE: OFF")
    else:
        typer.echo(f"MAINTENANCE: ON ({fmt_seconds(maint_left)} rimanenti)")


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


@app.command()
def mute(duration: str = typer.Argument("10m", help="Esempio: 10m, 30m, 1h")):
    """Silenzia popup (solo CRITICAL) per un periodo."""
    seconds = parse_duration(duration)
    db.set_flag("mute", "1", ttl_seconds=seconds)
    typer.echo(f"MUTE attivo per {duration}")


@app.command()
def maintenance(duration: str = typer.Argument("30m", help="Esempio: 30m, 1h")):
    """Modalità manutenzione: riduce rumore per un periodo."""
    seconds = parse_duration(duration)
    db.set_flag("maintenance", "1", ttl_seconds=seconds)
    typer.echo(f"MAINTENANCE attivo per {duration}")
