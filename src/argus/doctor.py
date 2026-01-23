from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import typer

from argus import __version__ as ARGUS_VERSION
from argus import db, paths
from argus.doctor_notify import (
    collect_notify_diagnostics,
    render_notify_issue,
    render_notify_text,
)

# ---------------------------
# Model
# ---------------------------

@dataclass
class CheckResult:
    name: str
    status: str  # OK | WARN | FAIL
    detail: str = ""
    advice: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["advice"] = self.advice or []
        return d


@dataclass
class PerfResult:
    name: str
    status: str  # OK | WARN | FAIL
    ms: float
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "status": self.status, "ms": round(self.ms, 2), "detail": self.detail}


def _icon(status: str) -> str:
    s = (status or "").upper()
    if s == "OK":
        return "✅"
    if s == "WARN":
        return "⚠️"
    return "❌"


def _run(cmd: List[str], timeout: float = 2.0) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return 127, "", f"{e!r}"


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _get_os_release() -> Dict[str, str]:
    out: Dict[str, str] = {}
    p = Path("/etc/os-release")
    if not p.exists():
        return out
    try:
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    except Exception:
        return out
    return out


def _pkg_manager() -> str:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("yum"):
        return "yum"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("zypper"):
        return "zypper"
    return ""


def _get_group_names() -> List[str]:
    if not _is_linux():
        return []
    try:
        import grp  # pylint: disable=import-error
        gids = os.getgroups()
        out: List[str] = []
        for gid in gids:
            try:
                out.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
        return out
    except Exception:
        return []


# ---------------------------
# Checks
# ---------------------------

def _check_python() -> CheckResult:
    py = sys.executable
    ver = ".".join(map(str, sys.version_info[:3]))
    venv = os.environ.get("VIRTUAL_ENV", "")
    venv_txt = f"venv={venv}" if venv else "venv=(none)"
    return CheckResult(
        name="Python runtime",
        status="OK",
        detail=f"python={py}  version={ver}  argus={ARGUS_VERSION}  {venv_txt}",
    )


def _check_dirs() -> CheckResult:
    try:
        paths.ensure_dirs()
        rep = Path.home() / ".local/share/argus/reports"
        rep.mkdir(parents=True, exist_ok=True)
        return CheckResult(
            name="ARGUS directories",
            status="OK",
            detail=f"~/.local/share/argus exists; reports={rep}",
        )
    except Exception as e:
        return CheckResult(
            name="ARGUS directories",
            status="FAIL",
            detail=f"Failed to ensure dirs: {e!r}",
            advice=["Check $HOME permissions and filesystem health."],
        )


def _check_config() -> CheckResult:
    try:
        from argus.config import ensure_config_exists  # type: ignore
        ensure_config_exists()
        return CheckResult(
            name="ARGUS config",
            status="OK",
            detail="Config ensured (argus.config.ensure_config_exists).",
        )
    except Exception as e:
        return CheckResult(
            name="ARGUS config",
            status="WARN",
            detail=f"Could not ensure config: {e!r}",
            advice=[
                "If ARGUS still runs fine, you can ignore this warning.",
                "Otherwise verify argus.config and default config generation.",
            ],
        )


def _check_db() -> CheckResult:
    try:
        db.init_db()
        _ = db.list_events(limit=1)
        return CheckResult(
            name="ARGUS database",
            status="OK",
            detail="DB initialized and readable.",
        )
    except Exception as e:
        return CheckResult(
            name="ARGUS database",
            status="FAIL",
            detail=f"DB init/read failed: {e!r}",
            advice=[
                "Check file permissions under ~/.local/share/argus/",
                "Try deleting DB only if you accept losing events (dev mode).",
            ],
        )


def _check_tools() -> CheckResult:
    needed = ["systemctl", "journalctl", "ip"]
    nice = ["ss"]  # optional
    missing_needed = [x for x in needed if shutil.which(x) is None]
    missing_nice = [x for x in nice if shutil.which(x) is None]

    if missing_needed:
        return CheckResult(
            name="System tools",
            status="FAIL",
            detail=f"Missing required tools: {', '.join(missing_needed)}",
            advice=["Install systemd/journalctl/iproute2 tools (varies by distro)."],
        )

    status = "OK" if not missing_nice else "WARN"
    detail = "All required tools found."
    advice: List[str] = []

    if missing_nice:
        detail += f" Optional missing: {', '.join(missing_nice)}"
        if "ss" in missing_nice:
            advice.append("Listener scan may be limited: install iproute2 (usually provides ss).")

    return CheckResult(name="System tools", status=status, detail=detail, advice=advice)


def _check_authlog_readable(log_path: str) -> CheckResult:
    p = Path(log_path)
    if not p.exists():
        return CheckResult(
            name="auth.log readability",
            status="WARN",
            detail=f"{log_path} not found.",
            advice=[
                "On some distros SSH logs are only in journald. That’s OK.",
                "If you expect a file, verify rsyslog and auth facility configuration.",
            ],
        )

    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            _ = f.read(256)
        return CheckResult(
            name="auth.log readability",
            status="OK",
            detail=f"Readable: {log_path}",
        )
    except PermissionError:
        groups = _get_group_names()
        in_adm = "adm" in groups
        return CheckResult(
            name="auth.log readability",
            status="FAIL",
            detail=f"Permission denied on {log_path}. groups={groups or ['?']}",
            advice=[
                "Ubuntu typical fix:",
                "  sudo usermod -aG adm $USER",
                "  then logout/login (or reboot).",
                f"'adm' group present: {'YES' if in_adm else 'NO'}",
            ],
        )
    except Exception as e:
        return CheckResult(
            name="auth.log readability",
            status="WARN",
            detail=f"Could not read {log_path}: {e!r}",
            advice=["If SEC-01/02/03 are important, fix log access first."],
        )


def _check_env_for_notifications() -> CheckResult:
    """
    Notifications are DBus-session based.
    DISPLAY is not strictly required (Wayland).
    We mainly need XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS.
    """
    dbus = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    wayland = os.environ.get("WAYLAND_DISPLAY", "")
    display = os.environ.get("DISPLAY", "")
    sess = os.environ.get("XDG_SESSION_TYPE", "")

    missing: List[str] = []
    if not xdg:
        missing.append("XDG_RUNTIME_DIR")
    if not dbus:
        missing.append("DBUS_SESSION_BUS_ADDRESS")

    has_gui_hint = bool(wayland or display or sess)

    if not missing and has_gui_hint:
        return CheckResult(
            name="Desktop session env",
            status="OK",
            detail=f"DBUS/XDG present; session={sess or '?'} wayland={wayland or '(no)'} display={display or '(no)'}",
        )

    if not missing and not has_gui_hint:
        return CheckResult(
            name="Desktop session env",
            status="WARN",
            detail="DBUS/XDG present, but no GUI hints (WAYLAND/DISPLAY/XDG_SESSION_TYPE). Headless runs may not show popups.",
            advice=[
                "If you're running the systemd --user service inside a graphical login, ignore this.",
                "Quick test: argus notify-test",
            ],
        )

    return CheckResult(
        name="Desktop session env",
        status="WARN",
        detail=f"Missing env: {', '.join(missing)} (may break desktop notifications in systemd --user service).",
        advice=[
            "Recommended fix (systemd --user override):",
            "  systemctl --user edit argus.service",
            "  [Service]",
            "  Environment=XDG_RUNTIME_DIR=%t",
            "  Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus",
            "  systemctl --user daemon-reload",
            "  systemctl --user restart argus.service",
        ],
    )


def _check_systemd_user_service(service_name: str, fix_systemd: bool, verbose: bool) -> CheckResult:
    if not _is_linux():
        return CheckResult(
            name="systemd user service",
            status="WARN",
            detail="Not running on Linux (systemd user checks skipped).",
        )

    if shutil.which("systemctl") is None:
        return CheckResult(
            name="systemd user service",
            status="FAIL",
            detail="systemctl not found.",
            advice=["Install systemd or run ARGUS in foreground mode."],
        )

    if fix_systemd:
        _run(["systemctl", "--user", "daemon-reload"], timeout=3.0)
        _run(["systemctl", "--user", "enable", "--now", service_name], timeout=4.0)

    rc_en, out_en, err_en = _run(["systemctl", "--user", "is-enabled", service_name], timeout=2.0)
    rc_ac, out_ac, err_ac = _run(["systemctl", "--user", "is-active", service_name], timeout=2.0)

    enabled = (out_en or "").strip()
    active = (out_ac or "").strip()

    if rc_en != 0 and "not-found" in (out_en + err_en):
        return CheckResult(
            name="systemd user service",
            status="FAIL",
            detail=f"Unit not found: {service_name}",
            advice=[
                "Install/copy the unit file into:",
                "  ~/.config/systemd/user/argus.service",
                "Then run:",
                "  systemctl --user daemon-reload",
                "  systemctl --user enable --now argus.service",
            ],
        )

    if enabled != "enabled" or active != "active":
        status = "WARN" if enabled in ("enabled", "static") else "FAIL"
        detail = f"{service_name}: enabled={enabled or '?'} active={active or '?'}"
        if verbose:
            detail += (
                f"\n  is-enabled: rc={rc_en} out={out_en} err={err_en}"
                f"\n  is-active:  rc={rc_ac} out={out_ac} err={err_ac}"
            )
        return CheckResult(
            name="systemd user service",
            status=status,
            detail=detail,
            advice=[
                "To enable and start:",
                "  systemctl --user daemon-reload",
                "  systemctl --user enable --now argus.service",
                "To see logs:",
                "  journalctl --user -u argus.service -n 80 --no-pager",
            ],
        )

    return CheckResult(
        name="systemd user service",
        status="OK",
        detail=f"{service_name}: enabled=enabled active=active",
        advice=["Logs: journalctl --user -u argus.service -n 80 --no-pager"],
    )


# ---------------------------
# Perf
# ---------------------------

def _timed(name: str, fn: Callable[[], Any], warn_ms: float, fail_ms: float) -> PerfResult:
    t0 = time.perf_counter()
    try:
        _ = fn()
        dt = (time.perf_counter() - t0) * 1000.0
        status = "OK" if dt <= warn_ms else ("WARN" if dt <= fail_ms else "FAIL")
        return PerfResult(name=name, status=status, ms=dt)
    except Exception as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return PerfResult(name=name, status="WARN", ms=dt, detail=f"{e!r}")


def _run_perf() -> List[PerfResult]:
    perf: List[PerfResult] = []

    # Collectors
    def mem_snap():
        from argus.collectors.memory import snapshot as memory_snapshot
        return memory_snapshot()

    def cpu_temp():
        from argus.collectors.temperature import read_cpu_temp_c
        return read_cpu_temp_c()

    def disk_root():
        try:
            from argus.collectors.disk import root_used_pct
            return root_used_pct()
        except Exception:
            return None

    perf.append(_timed("collector.memory_snapshot()", mem_snap, warn_ms=25, fail_ms=250))
    perf.append(_timed("collector.read_cpu_temp_c()", cpu_temp, warn_ms=25, fail_ms=250))
    perf.append(_timed("collector.disk.root_used_pct()", disk_root, warn_ms=25, fail_ms=250))

    # Detectors (single safe poll)
    def det_temp_poll():
        from argus.detectors.hea_temperature import TemperatureDetector
        from argus.collectors.temperature import read_cpu_temp_c
        det = TemperatureDetector()
        t = read_cpu_temp_c()
        if t is None:
            t = 0.0
        return list(det.poll(t))

    def det_disk_poll():
        from argus.detectors.hea_disk import DiskUsageDetector
        det = DiskUsageDetector()
        return list(det.poll())

    def det_services_poll():
        from argus.detectors.hea_services import HeaServicesDetector
        det = HeaServicesDetector(interval_s=15)
        if hasattr(det, "poll"):
            return list(det.poll())  # type: ignore[attr-defined]
        return []

    def det_mem_poll():
        from argus.detectors.hea_memory import MemoryPressureDetector
        from argus.collectors.memory import snapshot as memory_snapshot
        det = MemoryPressureDetector()
        snap = memory_snapshot()
        return list(det.poll(snap))

    def det_sec_sample():
        # smoke test parsing
        from argus.detectors.sec01_ssh import SshBruteForceDetector
        from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
        from argus.detectors.sec03_sudo import SudoActivityDetector

        d1 = SshBruteForceDetector()
        d2 = SshSuccessAfterFailsDetector()
        d3 = SudoActivityDetector()

        sample_fail = "Jan 01 00:00:01 host sshd[123]: Failed password for invalid user test from 1.2.3.4 port 12345 ssh2"
        sample_ok = "Jan 01 00:00:10 host sshd[123]: Accepted password for antonio from 1.2.3.4 port 12345 ssh2"
        sample_sudo = "Jan 01 00:01:00 host sudo: antonio : TTY=pts/0 ; PWD=/home/antonio ; USER=root ; COMMAND=/bin/ls"

        d1.handle_line(sample_fail)
        d2.handle_line(sample_ok)
        d3.handle_line(sample_sudo)
        return True

    def det_listen_poll():
        from argus.detectors.sec04_listen import ListeningPortDetector
        det = ListeningPortDetector()
        return list(det.poll())

    def det_integrity_poll():
        from argus.detectors.sec05_file_integrity import FileIntegrityDetector
        det = FileIntegrityDetector()
        return list(det.poll())

    perf.append(_timed("detector.HEA temp poll()", det_temp_poll, warn_ms=60, fail_ms=500))
    perf.append(_timed("detector.HEA disk poll()", det_disk_poll, warn_ms=80, fail_ms=800))
    perf.append(_timed("detector.HEA services poll()", det_services_poll, warn_ms=200, fail_ms=1500))
    perf.append(_timed("detector.HEA memory poll()", det_mem_poll, warn_ms=80, fail_ms=800))
    perf.append(_timed("detector.SEC parse smoke()", det_sec_sample, warn_ms=40, fail_ms=400))
    perf.append(_timed("detector.SEC listen poll()", det_listen_poll, warn_ms=250, fail_ms=2000))
    perf.append(_timed("detector.SEC integrity poll()", det_integrity_poll, warn_ms=250, fail_ms=2000))

    return perf


# ---------------------------
# Copy/paste fixes
# ---------------------------

def _fix_blocks(results: List[CheckResult], notify_diag: Any) -> List[Tuple[str, List[str]]]:
    """
    Returns a list of (title, bash_lines) to show as copy/paste fixes.
    Only include blocks that are relevant to WARN/FAIL.
    """
    blocks: List[Tuple[str, List[str]]] = []
    by_name = {r.name: r for r in results}

    # notifications (DBus)
    try:
        if getattr(notify_diag, "ok", True) is False:
            fixes = list(getattr(notify_diag, "fixes", []) or [])
            if fixes:
                blocks.append(("Fix desktop notifications (DBus / systemd --user)", fixes))
    except Exception:
        pass

    # auth.log
    r = by_name.get("auth.log readability")
    if r and r.status.upper() == "FAIL":
        blocks.append(
            (
                "Fix auth.log permissions (Ubuntu/Debian typical)",
                [
                    "sudo usermod -aG adm $USER",
                    "# then logout/login (or reboot)",
                ],
            )
        )

    # systemd user service
    r = by_name.get("systemd user service")
    if r and r.status.upper() in ("WARN", "FAIL"):
        blocks.append(
            (
                "Enable/start ARGUS user service",
                [
                    "systemctl --user daemon-reload",
                    "systemctl --user enable --now argus.service",
                    "systemctl --user status argus.service --no-pager",
                    "journalctl --user -u argus.service -n 80 --no-pager",
                ],
            )
        )

    # desktop env for notifications
    r = by_name.get("Desktop session env")
    if r and r.status.upper() == "WARN":
        blocks.append(
            (
                "Set DBus session env in systemd --user (recommended)",
                [
                    "systemctl --user edit argus.service",
                    "# add:",
                    "# [Service]",
                    "# Environment=XDG_RUNTIME_DIR=%t",
                    "# Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus",
                    "systemctl --user daemon-reload",
                    "systemctl --user restart argus.service",
                ],
            )
        )

    return blocks


def _env_summary() -> Dict[str, Any]:
    osr = _get_os_release()
    return {
        "argus_version": ARGUS_VERSION,
        "python": sys.executable,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "os_release": osr,
        "venv": os.environ.get("VIRTUAL_ENV", ""),
    }


def _issue_markdown(
    results: List[CheckResult],
    perf: Optional[List[PerfResult]],
    fixes: List[Tuple[str, List[str]]],
) -> str:
    env = _env_summary()

    lines: List[str] = []
    lines.append("### ARGUS Doctor Report")
    lines.append("")

    lines.append("**Environment**")
    lines.append("")
    lines.append("```text")
    lines.append(f"argus_version: {env.get('argus_version')}")
    lines.append(f"python: {env.get('python')}")
    lines.append(f"python_version: {env.get('python_version')}")
    lines.append(f"platform: {env.get('platform')}")
    lines.append(f"kernel: {env.get('kernel')}")
    venv = env.get("venv") or "(none)"
    lines.append(f"venv: {venv}")
    osr = env.get("os_release") or {}
    if osr:
        pretty = osr.get("PRETTY_NAME") or ""
        if pretty:
            lines.append(f"os: {pretty}")
    lines.append("```")
    lines.append("")

    lines.append("**Checks**")
    lines.append("")
    lines.append("| Check | Status | Detail |")
    lines.append("|---|---:|---|")
    for r in results:
        detail = (r.detail or "").replace("\n", "<br>")
        lines.append(f"| {r.name} | **{r.status}** | {detail} |")
    lines.append("")

    if perf is not None:
        lines.append("**Perf (one-shot, safe)**")
        lines.append("")
        lines.append("| Step | Status | ms | Detail |")
        lines.append("|---|---:|---:|---|")
        for p in perf:
            d = (p.detail or "").replace("\n", "<br>")
            lines.append(f"| `{p.name}` | **{p.status}** | {p.ms:.2f} | {d} |")
        lines.append("")

    if fixes:
        lines.append("**Copy/paste fixes**")
        lines.append("")
        for title, cmds in fixes:
            lines.append(f"**{title}**")
            lines.append("")
            lines.append("```bash")
            for c in cmds:
                lines.append(c)
            lines.append("```")
            lines.append("")
    else:
        lines.append("**Copy/paste fixes**")
        lines.append("")
        lines.append("_No fixes suggested (all OK or only informational warnings)._")
        lines.append("")

    return "\n".join(lines)


# ---------------------------
# Runner
# ---------------------------

def run_doctor(
    *,
    log_path: str = "/var/log/auth.log",
    service_name: str = "argus.service",
    verbose: bool = False,
    json_out: bool = False,
    fix_systemd: bool = False,
    perf: bool = False,
    issue: bool = False,
) -> int:
    """
    Exit codes:
      0 = all OK
      1 = warnings but no failures
      2 = at least one failure
    """
    results: List[CheckResult] = []

    # Core checks
    results.append(_check_python())
    results.append(_check_dirs())
    results.append(_check_config())
    results.append(_check_db())
    results.append(_check_tools())
    results.append(_check_authlog_readable(log_path))
    results.append(_check_env_for_notifications())
    results.append(_check_systemd_user_service(service_name, fix_systemd=fix_systemd, verbose=verbose))

    # Notifications diagnostics (DBus)
    notify_diag = collect_notify_diagnostics(service_name=service_name)
    results.append(
        CheckResult(
            name="Desktop notifications (DBus)",
            status="OK" if getattr(notify_diag, "ok", False) else "WARN",
            detail=f"org.freedesktop.Notifications: {getattr(notify_diag, 'server', 'unknown')}",
            advice=(
                []
                if getattr(notify_diag, "ok", False)
                else (list(getattr(notify_diag, "problems", []) or [])[:6] + ["Quick test: argus notify-test"])
            ),
        )
    )

    perf_results: Optional[List[PerfResult]] = None
    if perf:
        perf_results = _run_perf()

    # Exit code from checks (NOT perf)
    has_fail = any(r.status.upper() == "FAIL" for r in results)
    has_warn = any(r.status.upper() == "WARN" for r in results)
    exit_code = 2 if has_fail else (1 if has_warn else 0)

    fixes = _fix_blocks(results, notify_diag)

    if json_out:
        payload = {
            "argus_version": ARGUS_VERSION,
            "exit_code": exit_code,
            "env": _env_summary(),
            "results": [r.to_dict() for r in results],
            "perf": [p.to_dict() for p in perf_results] if perf_results is not None else None,
            "fixes": [{"title": t, "commands": c} for t, c in fixes],
            "notifications": {
                "ok": getattr(notify_diag, "ok", False),
                "server": getattr(notify_diag, "server", "unknown"),
                "env": getattr(notify_diag, "env", {}) or {},
                "problems": getattr(notify_diag, "problems", []) or [],
                "fixes": getattr(notify_diag, "fixes", []) or [],
            },
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return exit_code

    if issue:
        md = _issue_markdown(results, perf_results, fixes)
        md += "\n\n" + "\n".join(render_notify_issue(notify_diag))
        typer.echo(md)
        return exit_code

    # Human output
    typer.echo(f"ARGUS Doctor — v{ARGUS_VERSION}")
    typer.echo("-" * 60)

    for r in results:
        typer.echo(f"{_icon(r.status)} {r.name}: {r.status}")
        if r.detail:
            for ln in str(r.detail).splitlines():
                typer.echo(f"    {ln}")
        if r.advice:
            typer.echo("    Suggested:")
            for a in r.advice:
                typer.echo(f"      - {a}")
        typer.echo("")

    # Extra notification details (only if not OK)
    if getattr(notify_diag, "ok", False) is False:
        typer.echo("Notifications (details)")
        typer.echo("-" * 60)
        for ln in render_notify_text(notify_diag, show_fixes=True):
            typer.echo(ln)
        typer.echo("")

    if perf_results is not None:
        typer.echo("Perf (one-shot, safe)")
        typer.echo("-" * 60)
        for p in perf_results:
            line = f"{_icon(p.status)} {p.name}: {p.status}  ({p.ms:.2f} ms)"
            typer.echo(line)
            if p.detail:
                typer.echo(f"    {p.detail}")
        typer.echo("")

    if fixes:
        typer.echo("Copy/paste fixes")
        typer.echo("-" * 60)
        for title, cmds in fixes:
            typer.echo(f"[{title}]")
            for c in cmds:
                typer.echo(f"  {c}")
            typer.echo("")
    else:
        typer.echo("Copy/paste fixes")
        typer.echo("-" * 60)
        typer.echo("  (none)")
        typer.echo("")

    typer.echo("-" * 60)
    if exit_code == 0:
        typer.echo("✅ All checks OK.")
    elif exit_code == 1:
        typer.echo("⚠️ Warnings detected (ARGUS likely works, but review items above).")
    else:
        typer.echo("❌ Failures detected (fix items above).")

    return exit_code


__all__ = ["run_doctor"]
