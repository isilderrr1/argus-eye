from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Optional

import typer
from argus import __version__, db, paths
from argus.monitor import run_authlog_security

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    help=(
        "ARGUS — Linux security + health monitor (TUI + CLI).\n\n"
        "Run without subcommands to open the dashboard (TUI)."
    ),
)

debug_app = typer.Typer(
    help="Developer/debug commands (may be noisy).",
    add_completion=False,
)

app.add_typer(debug_app, name="debug")

_DUR_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)


def parse_duration(s: str) -> int:
    """Parse duration like: 30s, 10m, 1h, 2d -> seconds."""
    m = _DUR_RE.match(s or "")
    if not m:
        raise typer.BadParameter("Invalid duration. Use: 30s, 10m, 1h, 2d")
    n = int(m.group(1))
    unit = m.group(2).lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def fmt_seconds(sec: int) -> str:
    """Human-friendly seconds (e.g. 9m12s / 1h05m)."""
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
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    paths.ensure_dirs()
    db.init_db()

    from argus.config import ensure_config_exists

    ensure_config_exists()

    if version:
        typer.echo(f"argus {__version__}")
        raise typer.Exit(code=0)

    # No subcommand -> open TUI
    if ctx.invoked_subcommand is None:
        from argus.tui import ArgusApp

        ArgusApp().run()
        raise typer.Exit(code=0)


# ----------------------------
# User-facing commands
# ----------------------------

@app.command()
def status() -> None:
    """Show monitor state (RUNNING/STOPPED) and runtime flags."""
    state = get_state()
    mute_left = db.remaining_seconds("mute")
    maint_left = db.remaining_seconds("maintenance")

    typer.echo(f"STATE: {state}")
    typer.echo("MUTE: OFF" if mute_left is None else f"MUTE: ON ({fmt_seconds(mute_left)} remaining)")
    typer.echo("MAINTENANCE: OFF" if maint_left is None else f"MAINTENANCE: ON ({fmt_seconds(maint_left)} remaining)")


@app.command()
def start() -> None:
    """Start monitor (v1 placeholder)."""
    set_state("RUNNING")
    typer.echo("RUNNING")


@app.command()
def stop() -> None:
    """Stop monitor (v1 placeholder)."""
    set_state("STOPPED")
    typer.echo("STOPPED")


@app.command()
def mute(
    duration: str = typer.Argument("10m", help="Examples: 10m, 30m, 1h"),
) -> None:
    """Mute CRITICAL popups for a period."""
    ttl = parse_duration(duration)
    db.set_flag("mute", "1", ttl_seconds=ttl)
    typer.echo(f"MUTE enabled for {duration}")


@app.command()
def maintenance(
    duration: str = typer.Argument("30m", help="Examples: 30m, 1h"),
) -> None:
    """Maintenance mode: reduces noise for a period."""
    ttl = parse_duration(duration)
    db.set_flag("maintenance", "1", ttl_seconds=ttl)
    typer.echo(f"MAINTENANCE enabled for {duration}")


@app.command()
def run(
    log_path: str = typer.Option(
        "/var/log/auth.log",
        help="SSH/auth log path (Ubuntu default: /var/log/auth.log).",
    ),
) -> None:
    """
    Run the monitor in foreground.

    Includes:
      - Security: SEC-01..SEC-05 (auth log + periodic scans)
      - Health: HEA-01/02 (CPU temp), HEA-03 (disk), HEA-04 (services)
    """
    set_state("RUNNING")
    try:
        run_authlog_security(log_path=log_path)
    finally:
        set_state("STOPPED")


@app.command("report")
def report(
    n: int = typer.Option(
        1,
        "-n",
        "--last",
        min=1,
        help="Generate/print reports for the last N events (batch).",
    ),
    nth: Optional[int] = typer.Option(
        None,
        "--nth",
        min=1,
        help="Pick the Nth most recent event (1=latest, 2=previous...).",
    ),
    code: Optional[str] = typer.Option(
        None,
        "--code",
        help="Filter by event code (e.g., HEA-04, SEC-03).",
    ),
    list_only: bool = typer.Option(
        False,
        "--list",
        "-l",
        help="List saved reports from ~/.local/share/argus/reports and exit.",
    ),
) -> None:
    """
    Print a markdown report for events.

    - Default: report for the latest event
    - --nth: report for the Nth latest event (single)
    - -n/--last: batch mode (last N events)
    - --code: filter by code, works with both modes
    - -l/--list: list saved reports on disk (does not print reports)
    """
    from argus import reporter

    db.init_db()

    # LIST saved reports (from reports dir), do not touch events DB
    if list_only:
        reps = reporter.list_saved_reports(code=code)
        if not reps:
            typer.echo("No saved reports found.")
            raise typer.Exit(code=0)

        typer.echo(f"Saved reports: {len(reps)}")
        typer.echo("Idx  Time                Code    Severity   Entity              File")
        typer.echo("---- ------------------- ------- ---------- ------------------- ------------------------------")

        for i, r in enumerate(reps, start=1):
            ent = (r.get("entity") or "")[:19]
            typer.echo(
                f"{i:>3}  {r['time']:<19} {r['code']:<7} {r['severity']:<10} {ent:<19} {r['file']}"
            )
        raise typer.Exit(code=0)

    # Otherwise: generate/print report(s) from events DB
    events = db.list_events(limit=500)

    if code:
        code_u = code.upper().strip()
        events = [e for e in events if (str(e.get("code") or "")).upper() == code_u]

    if not events:
        typer.echo("No events found.")
        raise typer.Exit(code=1)

    # SINGLE PICK mode
    if nth is not None:
        idx = nth - 1
        if idx < 0 or idx >= len(events):
            typer.echo(f"Not enough events to pick --nth {nth} (available: {len(events)}).")
            raise typer.Exit(code=1)

        e = events[idx]
        typer.echo(reporter.render_markdown(e))
        raise typer.Exit(code=0)

    # Default single (latest)
    if n == 1:
        typer.echo(reporter.render_markdown(events[0]))
        raise typer.Exit(code=0)

    # BATCH mode (last N)
    picked = events[:n]
    for i, e in enumerate(picked, start=1):
        if i > 1:
            typer.echo("\n" + ("-" * 60) + "\n")
        typer.echo(reporter.render_markdown(e))


# ----------------------------
# Debug commands (clean help)
# ----------------------------

@debug_app.command("events")
def debug_events(
    last: int = typer.Option(20, "--last", "-n", help="Number of events to show (default 20)."),
) -> None:
    """Show latest events from DB (debug/dev)."""
    rows = db.list_events(limit=last)
    if not rows:
        typer.echo("No events in DB.")
        raise typer.Exit(code=0)

    for e in rows:
        ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
        sev = (e.get("severity") or "").upper()
        code = (e.get("code") or "")
        msg = (e.get("message") or "").strip()
        if len(msg) > 140:
            msg = msg[:137] + "..."
        typer.echo(f"{ts}  {sev:<8} {code:<6} {msg}")


@debug_app.command("sec02")
def debug_sec02(
    log_path: str = typer.Option(
        "/var/log/auth.log",
        help="SSH/auth log path (Ubuntu default: /var/log/auth.log).",
    ),
) -> None:
    """Run only SEC-02 detector (debug)."""
    set_state("RUNNING")

    from argus.collectors.authlog import tail_file
    from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector

    detector = SshSuccessAfterFailsDetector()

    try:
        typer.echo(f"[argus] DEBUG sec02 monitor -> {log_path}")
        typer.echo("[argus] Press CTRL+C to stop.")
        time.sleep(0.2)

        for line in tail_file(log_path, from_end=True):
            result = detector.handle_line(line)
            if result:
                severity, entity, message = result
                db.add_event(code="SEC-02", severity=severity, message=message, entity=str(entity))
                typer.echo(f"[SEC-02] {severity:<8} {entity}  {message}")

    except PermissionError:
        typer.echo(f"[argus] Permission denied: {log_path}")
        typer.echo("[argus] Typical Ubuntu fix: add your user to 'adm':")
        typer.echo("        sudo usermod -aG adm $USER")
        typer.echo("        then logout/login (or reboot).")
        raise
    except KeyboardInterrupt:
        typer.echo("\n[argus] Stop requested (CTRL+C).")
    finally:
        set_state("STOPPED")


# ----------------------------
# Backward compatible aliases (hidden)
# ----------------------------

@app.command("events", hidden=True)
def events_alias(
    last: int = typer.Option(20, "--last", "-n", help="Number of events to show (default 20)."),
) -> None:
    debug_events(last=last)


@app.command("sec02", hidden=True)
def sec02_alias(
    log_path: str = typer.Option("/var/log/auth.log", help="SSH/auth log path."),
) -> None:
    debug_sec02(log_path=log_path)
