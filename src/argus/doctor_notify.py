from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class NotifyDiag:
    ok: bool
    server: str
    env: Dict[str, str]
    problems: List[str]
    fixes: List[str]


def _run(cmd: List[str], timeout: float = 1.5) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return 99, "", f"{e!r}"


def _probe_notifications_server() -> tuple[bool, str, List[str]]:
    """
    Tries to contact org.freedesktop.Notifications via gdbus (no popup).
    Returns (ok, server_info, problems)
    """
    problems: List[str] = []

    if shutil.which("gdbus") is None:
        problems.append("gdbus not found (optional probe tool). Install: sudo apt install libglib2.0-bin")
        return False, "", problems

    cmd = [
        "gdbus", "call",
        "--session",
        "--dest", "org.freedesktop.Notifications",
        "--object-path", "/org/freedesktop/Notifications",
        "--method", "org.freedesktop.Notifications.GetServerInformation",
    ]
    rc, out, err = _run(cmd, timeout=1.8)
    if rc != 0:
        problems.append("Cannot reach org.freedesktop.Notifications on session bus (gdbus call failed).")
        if err.strip():
            problems.append(f"gdbus: {err.strip()[:220]}")
        return False, "", problems

    # Typical output: "('GNOME Shell', 'gnome-shell', '45.2', '1.2')"
    s = out.strip()
    m = re.search(r"\('([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\)", s)
    if m:
        name, vendor, version, spec = m.groups()
        return True, f"{name} ({vendor}) v{version}, spec {spec}", problems

    return True, s, problems


def collect_notify_diagnostics(service_name: str = "argus.service") -> NotifyDiag:
    """
    Collect diagnostics for desktop notifications in a systemd --user context.
    Does NOT send a popup. It only probes the notification server.
    """
    env = {
        "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", ""),
        "DBUS_SESSION_BUS_ADDRESS": os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""),
        "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", ""),
        "DISPLAY": os.environ.get("DISPLAY", ""),
        "XDG_SESSION_TYPE": os.environ.get("XDG_SESSION_TYPE", ""),
    }

    problems: List[str] = []
    fixes: List[str] = []

    # DBus env is the main requirement for session notifications
    if not env["XDG_RUNTIME_DIR"]:
        problems.append("XDG_RUNTIME_DIR is missing (session bus path may be unknown).")
    if not env["DBUS_SESSION_BUS_ADDRESS"]:
        problems.append("DBUS_SESSION_BUS_ADDRESS is missing (cannot talk to session bus).")

    ok_server, server_info, server_problems = _probe_notifications_server()
    problems.extend(server_problems)

    # Success criteria: server reachable (best signal).
    ok = ok_server and (not problems or True)

    # Fixes: keep them copy/paste-ready, optimized for systemd --user
    fixes.append("# Test a CRITICAL popup now:")
    fixes.append("argus notify-test")

    fixes.append("")
    fixes.append("# If argus runs as a systemd --user service and notifications fail, ensure DBus env inside the service:")
    fixes.append("systemctl --user edit " + service_name)
    fixes.append("# Paste this override, then save & exit:")
    fixes.append("[Service]")
    fixes.append("Environment=XDG_RUNTIME_DIR=%t")
    fixes.append("Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus")
    fixes.append("")
    fixes.append("# Reload + restart:")
    fixes.append("systemctl --user daemon-reload")
    fixes.append("systemctl --user restart " + service_name)

    return NotifyDiag(
        ok=ok_server,  # server reachability is the main OK/FAIL
        server=server_info or "(unknown)",
        env=env,
        problems=problems,
        fixes=fixes,
    )


def render_notify_text(diag: NotifyDiag, show_fixes: bool = False) -> List[str]:
    lines: List[str] = []
    badge = "OK" if diag.ok else "FAIL"
    lines.append(f"[Notifications] {badge}  org.freedesktop.Notifications: {diag.server}")

    # quick env note (useful for debugging service context)
    env_bits = []
    if diag.env.get("XDG_SESSION_TYPE"):
        env_bits.append(f"session={diag.env['XDG_SESSION_TYPE']}")
    if diag.env.get("WAYLAND_DISPLAY"):
        env_bits.append(f"wayland={diag.env['WAYLAND_DISPLAY']}")
    if diag.env.get("DISPLAY"):
        env_bits.append(f"display={diag.env['DISPLAY']}")
    if env_bits:
        lines.append("  env: " + ", ".join(env_bits))

    if diag.problems and not diag.ok:
        lines.append("  problems:")
        for p in diag.problems[:6]:
            lines.append(f"    - {p}")

    if show_fixes:
        lines.append("  copy/paste fixes:")
        for fx in diag.fixes:
            lines.append("    " + fx)

    return lines


def render_notify_issue(diag: NotifyDiag) -> List[str]:
    lines: List[str] = []
    lines.append("### Desktop notifications")
    lines.append(f"- org.freedesktop.Notifications: {'OK' if diag.ok else 'FAIL'} — {diag.server}")
    lines.append("- env:")
    for k in ("XDG_SESSION_TYPE", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY", "DISPLAY"):
        v = diag.env.get(k, "")
        vv = (v[:160] + "…") if len(v) > 160 else v
        lines.append(f"  - {k}: `{vv or '(empty)'}`")
    if diag.problems and not diag.ok:
        lines.append("- problems:")
        for p in diag.problems[:10]:
            lines.append(f"  - {p}")
    lines.append("")
    lines.append("Suggested quick test:")
    lines.append("```bash")
    lines.append("argus notify-test")
    lines.append("```")
    return lines
