from __future__ import annotations

import time
import typer
from datetime import datetime
from argus import db

from argus import __version__, paths, db
from argus.collectors.authlog import tail_file
from argus.detectors.sec01_ssh import SshBruteForceDetector
from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
from argus.detectors.sec03_sudo import SudoActivityDetector
from argus.monitor import run_authlog_security  # <-- import corretto


app = typer.Typer(add_completion=False, invoke_without_command=True)


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
    paths.ensure_dirs()
    db.init_db()

    from argus.config import ensure_config_exists
    ensure_config_exists()

    if version:
        typer.echo(f"argus {__version__}")
        raise typer.Exit()

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
    typer.echo("MUTE: OFF" if mute_left is None else f"MUTE: ON ({fmt_seconds(mute_left)} rimanenti)")
    typer.echo("MAINTENANCE: OFF" if maint_left is None else f"MAINTENANCE: ON ({fmt_seconds(maint_left)} rimanenti)")


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
    seconds = int(time.time()) + parse_duration(duration)
    db.set_flag("mute", "1", ttl_seconds=seconds)
    typer.echo(f"MUTE attivo per {duration}")


@app.command()
def maintenance(duration: str = typer.Argument("30m", help="Esempio: 30m, 1h")):
    """Modalità manutenzione: riduce rumore per un periodo."""
    seconds = parse_duration(duration)
    db.set_flag("maintenance", "1", ttl_seconds=seconds)
    typer.echo(f"MAINTENANCE attivo per {duration}")


@app.command()
def sec02(
    log_path: str = typer.Option("/var/log/auth.log", help="Path log SSH (Ubuntu: /var/log/auth.log)"),
):
    """Esegui il detector SEC-02 (Success After Fails)"""
    set_state("RUNNING")
    detector = SshSuccessAfterFailsDetector()

    try:
        typer.echo(f"[argus] SEC-02 monitor (auth.log) -> {log_path}")
        typer.echo("[argus] Premi CTRL+C per fermare.")
        time.sleep(0.2)

        for line in tail_file(log_path, from_end=True):
            result = detector.handle_line(line)
            if result:
                severity, entity, message = result
                db.add_event(code="SEC-02", severity=severity, message=message, entity=entity)
                typer.echo(f"[SEC-02] {severity:<8} {entity}  {message}")

    except PermissionError:
        typer.echo(f"[argus] Permesso negato su {log_path}.")
        typer.echo("[argus] Soluzione tipica su Ubuntu: aggiungi l'utente al gruppo 'adm':")
        typer.echo("        sudo usermod -aG adm $USER")
        typer.echo("        poi fai logout/login (o riavvia).")
        raise
    except KeyboardInterrupt:
        typer.echo("\n[argus] Stop richiesto dall'utente. (CTRL+C)")


@app.command()
def run(
    log_path: str = typer.Option("/var/log/auth.log", help="Path log SSH (Ubuntu: /var/log/auth.log)"),
):
    """Esegui il monitor in foreground (SEC-01) leggendo i log reali."""
    set_state("RUNNING")
    try:
        run_authlog_security(log_path=log_path)  # <-- Chiama direttamente la funzione ora
    finally:
        set_state("STOPPED")

@app.command("events")
def events(
    last: int = typer.Option(20, "--last", "-n", help="Numero di eventi da mostrare (default 20)")
):
    """Mostra gli ultimi eventi dal DB (comando di debug/dev)."""
    rows = db.list_events(limit=last)
    if not rows:
        typer.echo("Nessun evento nel DB.")
        raise typer.Exit()

    for e in rows:
        ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
        sev = (e.get("severity") or "").upper()
        code = (e.get("code") or "")
        msg = (e.get("message") or "").strip()
        if len(msg) > 140:
            msg = msg[:137] + "..."
        typer.echo(f"{ts}  {sev:<8} {code:<6} {msg}")
