from __future__ import annotations

import re
import time
import shutil
import subprocess
from datetime import datetime
from typing import Optional, Dict

import typer

from argus import __version__, paths, db
from argus.collectors.authlog import tail_file
from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
from argus.monitor import run_authlog_security

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog="Tip: use `argus COMMAND -h` (or `--help`) to see all options and examples for that command.",
)


_DUR_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)
_SERVICE = "argus.service"


def parse_duration(s: str) -> int:
    """Parse durations like: 30s, 10m, 1h, 2d -> seconds."""
    m = _DUR_RE.match(s)
    if not m:
        raise typer.BadParameter("Invalid duration. Use: 30s, 10m, 1h, 2d")
    n = int(m.group(1))
    unit = m.group(2).lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def fmt_seconds(sec: int) -> str:
    """Human friendly seconds (e.g. 9m12s / 1h05m)."""
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


def _systemctl_user(args: list[str], timeout: float = 2.5) -> Optional[subprocess.CompletedProcess]:
    if shutil.which("systemctl") is None:
        return None
    try:
        return subprocess.run(
            ["systemctl", "--user", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None


def _systemd_available() -> bool:
    r = _systemctl_user(["is-system-running"], timeout=1.5)
    if r is None:
        return False
    # If systemd user bus isn't available you typically see "Failed to connect to bus"
    if (r.stderr or "").lower().find("failed to connect to bus") >= 0:
        return False
    return True


def _service_info() -> Optional[Dict[str, str]]:
    if not _systemd_available():
        return None
    r = _systemctl_user(
        ["show", _SERVICE, "--no-pager", "--property=ActiveState,SubState,UnitFileState,Result,ExecMainStatus"],
        timeout=2.0,
    )
    if r is None or r.returncode != 0:
        return None

    info: Dict[str, str] = {}
    for ln in (r.stdout or "").splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            info[k.strip()] = v.strip()
    return info


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
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
    """Show state (RUNNING/STOPPED) + runtime flags."""
    # Prefer systemd user service state when available
    info = _service_info()
    if info:
        active = (info.get("ActiveState") or "unknown").lower()
        sub = (info.get("SubState") or "unknown").lower()
        enabled = (info.get("UnitFileState") or "unknown").lower()

        if active == "active":
            state = "RUNNING"
        elif active in ("activating",):
            state = "STARTING"
        elif active in ("deactivating",):
            state = "STOPPING"
        else:
            state = "STOPPED"

        typer.echo(f"STATE: {state}")
        typer.echo(f"SERVICE: {active}/{sub}  enabled={enabled}")
    else:
        state = get_state()
        typer.echo(f"STATE: {state}")
        typer.echo("SERVICE: (systemd user not available)")

    mute_left = db.remaining_seconds("mute")
    maint_left = db.remaining_seconds("maintenance")

    typer.echo("MUTE: OFF" if mute_left is None else f"MUTE: ON ({fmt_seconds(mute_left)} remaining)")
    typer.echo("MAINTENANCE: OFF" if maint_left is None else f"MAINTENANCE: ON ({fmt_seconds(maint_left)} remaining)")

@app.command()
def doctor(
    log_path: str = typer.Option(
        "/var/log/auth.log",
        help="Auth log path to test readability (Ubuntu: /var/log/auth.log).",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show more command outputs."),
    json_out: bool = typer.Option(False, "--json", help="Output JSON only (machine-readable)."),
    fix_systemd: bool = typer.Option(
        False,
        "--fix-systemd",
        help="attempt to fix common systemd user service issues.",
    ),
    perf: bool = typer.Option(
        False,
        "--perf",
        help="Run safe one-shot performance checks (collectors + detectors).",
    ),
    issue: bool = typer.Option(
        False,
        "--issue",
        help="Output Markdown ready to paste in a GitHub issue.",
    ),
):
    """Run ARGUS self-diagnostics. Use `argus doctor -h` for --perf and --issue."""
    from argus.doctor import run_doctor

    code = run_doctor(
        log_path=log_path,
        service_name="argus.service",
        verbose=verbose,
        json_out=json_out,
        fix_systemd=fix_systemd,
        perf=perf,
        issue=issue,
    )
    raise typer.Exit(code=code)

@app.command("notify-test")
def notify_test() -> None:
    """Send a CRITICAL desktop notification test (also writes a SYS CRITICAL event)."""
    from argus.notify_test import run_notification_test

    ok = run_notification_test()
    if ok:
        typer.echo("OK: notification backend executed (check your desktop popup).")
    else:
        typer.echo("WARN: notification backend not available or failed (no popup).")


@app.command()
def start():
    """Start Argus via systemd user service."""
    if not _systemd_available():
        typer.echo("[argus] systemd user is not available. Use: argus run")
        raise typer.Exit(code=1)

    r = _systemctl_user(["start", _SERVICE], timeout=3.0)
    if r is None or r.returncode != 0:
        err = (r.stderr or "").strip() if r else ""
        typer.echo("[argus] Failed to start systemd service.")
        if err:
            typer.echo(err)
        typer.echo(f"[argus] Try: systemctl --user status {_SERVICE} --no-pager")
        raise typer.Exit(code=1)

    typer.echo("RUNNING")


@app.command()
def stop():
    """Stop Argus via systemd user service."""
    if not _systemd_available():
        typer.echo("[argus] systemd user is not available.")
        raise typer.Exit(code=1)

    r = _systemctl_user(["stop", _SERVICE], timeout=3.0)
    if r is None or r.returncode != 0:
        err = (r.stderr or "").strip() if r else ""
        typer.echo("[argus] Failed to stop systemd service.")
        if err:
            typer.echo(err)
        raise typer.Exit(code=1)

    typer.echo("STOPPED")


@app.command()
def enable():
    """Enable + start Argus at login (systemd user)."""
    if not _systemd_available():
        typer.echo("[argus] systemd user is not available.")
        raise typer.Exit(code=1)

    r = _systemctl_user(["enable", "--now", _SERVICE], timeout=4.0)
    if r is None or r.returncode != 0:
        err = (r.stderr or "").strip() if r else ""
        typer.echo("[argus] Failed to enable the service.")
        if err:
            typer.echo(err)
        raise typer.Exit(code=1)

    typer.echo("ENABLED")


@app.command()
def disable():
    """Disable + stop Argus (systemd user)."""
    if not _systemd_available():
        typer.echo("[argus] systemd user is not available.")
        raise typer.Exit(code=1)

    r = _systemctl_user(["disable", "--now", _SERVICE], timeout=4.0)
    if r is None or r.returncode != 0:
        err = (r.stderr or "").strip() if r else ""
        typer.echo("[argus] Failed to disable the service.")
        if err:
            typer.echo(err)
        raise typer.Exit(code=1)

    typer.echo("DISABLED")


@app.command()
def logs(
    lines: int = typer.Option(80, "--lines", "-n", help="How many log lines to show."),
    follow: bool = typer.Option(False, "--follow", "-f", help="Follow logs (live)."),
):
    """Show systemd journal logs for Argus service. Use `argus logs -h` for options."""
    cmd = ["journalctl", "--user", "-u", _SERVICE, "--no-pager", "-n", str(lines)]
    if follow:
        cmd.append("-f")
    raise typer.Exit(subprocess.call(cmd))


@app.command()
def mute(duration: str = typer.Argument("10m", help="Example: 10m, 30m, 1h")):
    """Mute popups (CRITICAL only) for a period."""
    ttl = parse_duration(duration)
    db.set_flag("mute", "1", ttl_seconds=ttl)
    typer.echo(f"MUTE enabled for {duration}")


@app.command()
def maintenance(duration: str = typer.Argument("30m", help="Example: 30m, 1h")):
    """Maintenance mode: reduces noise for a period."""
    ttl = parse_duration(duration)
    db.set_flag("maintenance", "1", ttl_seconds=ttl)
    typer.echo(f"MAINTENANCE enabled for {duration}")


@app.command()
def run(
    log_path: str = typer.Option("/var/log/auth.log", help="SSH log path (Ubuntu: /var/log/auth.log)"),
):
    """Run monitor in foreground (used by systemd service too)."""
    set_state("RUNNING")
    try:
        run_authlog_security(log_path=log_path)
    finally:
        set_state("STOPPED")


@app.command()
def sec02(
    log_path: str = typer.Option("/var/log/auth.log", help="SSH log path (Ubuntu: /var/log/auth.log)"),
):
    """Run SEC-02 detector (Success After Fails)."""
    set_state("RUNNING")
    detector = SshSuccessAfterFailsDetector()

    try:
        typer.echo(f"[argus] SEC-02 monitor (auth.log) -> {log_path}")
        typer.echo("[argus] Press CTRL+C to stop.")
        time.sleep(0.2)

        for line in tail_file(log_path, from_end=True):
            result = detector.handle_line(line)
            if result:
                severity, entity, message = result
                db.add_event(code="SEC-02", severity=severity, message=message, entity=str(entity))
                typer.echo(f"[SEC-02] {severity:<8} {entity}  {message}")

    except PermissionError:
        typer.echo(f"[argus] Permission denied on {log_path}.")
        typer.echo("[argus] Typical fix on Ubuntu: add user to group 'adm':")
        typer.echo("        sudo usermod -aG adm $USER")
        typer.echo("        then logout/login (or reboot).")
        raise
    except KeyboardInterrupt:
        typer.echo("\n[argus] Stop requested by user (CTRL+C).")
    finally:
        set_state("STOPPED")


@app.command("events")
def events(
    last: int = typer.Option(20, "--last", "-n", help="How many events to show (default 20)"),
):
    """Show latest events from DB (debug/dev). Use `argus events -h` to see filters/options."""
    rows = db.list_events(limit=last)
    if not rows:
        typer.echo("No events in DB.")
        raise typer.Exit()

    for e in rows:
        ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
        sev = (e.get("severity") or "").upper()
        code = (e.get("code") or "")
        msg = (e.get("message") or "").strip()
        if len(msg) > 140:
            msg = msg[:137] + "..."
        typer.echo(f"{ts}  {sev:<8} {code:<6} {msg}")


@app.command("report")
def report(
    n: int = typer.Option(
        1, "-n", "--last", min=1, help="Generate/print reports for the last N events (batch)."
    ),
    nth: Optional[int] = typer.Option(
        None, "--nth", min=1, help="Pick the Nth most recent event (1=latest, 2=previous...)."
    ),
    code: Optional[str] = typer.Option(
        None, "--code", help="Filter by event code (e.g., HEA-04, SEC-03)."
    ),
    list_only: bool = typer.Option(
        False, "--list", "-l", help="List saved reports from ~/.local/share/argus/reports and exit."
    ),
) -> None:
    """
    Print a markdown report for events. Use `argus report -h` to see filters/options.

    - Default: report for the latest events
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


def run_cli() -> None:
    app()


if __name__ == "__main__":
    run_cli()
