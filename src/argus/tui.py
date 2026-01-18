from __future__ import annotations

import subprocess
import time
from datetime import datetime
from typing import Dict, List

from textual.app import App, ComposeResult
from textual.reactive import reactive
from textual.widgets import Static, Footer

from argus import db
from argus.trust import add_sec04_trust


# --- ICONS (spec) ---
CODE_ICON: Dict[str, str] = {
    "SEC-01": "🚫🔑",
    "SEC-02": "🛡️🔑",
    "SEC-03": "🧨",
    "SEC-04": "👂🌐",
    "SEC-05": "🧬📄",
    # HEALTH placeholders (li implementiamo dopo)
    "HEA-01": "🌡",
    "HEA-02": "🔥",
    "HEA-03": "💽",
    "HEA-04": "🔁",
    "HEA-05": "🧱",
    "SYS": "🛈",
}

SEV_ICON = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "❗"}
SEV_STYLE = {"INFO": "cyan", "WARNING": "yellow", "CRITICAL": "red"}


def _midnight_ts() -> int:
    now = datetime.now()
    mid = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(mid.timestamp())


def _is_sec(code: str) -> bool:
    return code.startswith("SEC-")


def _is_hea(code: str) -> bool:
    return code.startswith("HEA-")


def _global_state(recent: List[dict]) -> str:
    # ultimi 10 minuti (spec: CALM/WATCHING/ALERT)
    if any((e.get("severity") or "").upper() == "CRITICAL" for e in recent):
        return "ALERT"
    if any((e.get("severity") or "").upper() == "WARNING" for e in recent):
        return "WATCHING"
    return "CALM"


def _score(recent: List[dict], kind: str) -> int:
    # scoring semplice v1: CRIT=30, WARN=10, INFO=0 (clamp 0..100)
    s = 0
    for e in recent:
        code = (e.get("code") or "")
        if kind == "sec" and not _is_sec(code):
            continue
        if kind == "hea" and not _is_hea(code):
            continue
        sev = (e.get("severity") or "").upper()
        if sev == "CRITICAL":
            s += 30
        elif sev == "WARNING":
            s += 10
    return max(0, min(100, s))


def _status_runstop() -> str:
    # per ora è lo stato CLI (milestone 7 renderà start/stop "veri")
    try:
        r = subprocess.run(["argus", "status"], capture_output=True, text=True, timeout=1.5)
        out = (r.stdout or "").strip().splitlines()
        if out:
            return out[0].strip()
    except Exception:
        pass
    return "UNKNOWN"


def _flag_badge(flag_name: str) -> str:
    v = db.get_flag(flag_name)
    return flag_name.upper() if v else ""


def _fmt_event_line(e: dict) -> str:
    ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
    sev = (e.get("severity") or "INFO").upper()
    code = (e.get("code") or "")
    msg = (e.get("message") or "").strip()

    icon = CODE_ICON.get(code, "•")
    sev_i = SEV_ICON.get(sev, "•")
    color = SEV_STYLE.get(sev, "white")

    msg_short = msg if len(msg) <= 110 else (msg[:107] + "...")
    return f"{ts}  [{color}]{sev_i} {sev:<8}[/{color}] {icon} [dim]{code}[/dim]  {msg_short}"


def _fmt_kpi_line(state: str, threat: int, health: int, temp: str, disk: str, run: str) -> str:
    mute = _flag_badge("mute")
    maint = _flag_badge("maintenance")
    mm = []
    if mute:
        mm.append("MUTE")
    if maint:
        mm.append("MAINT")
    mm_txt = (" | " + "/".join(mm)) if mm else ""

    return (
        f"👁 [bold]ARGUS[/bold] | [bold]{state}[/bold] | "
        f"Threat [bold]{threat}/100[/bold] | Health [bold]{health}/100[/bold] | "
        f"🌡 {temp} | 💽 {disk} | 🔔 CRIT | {run}{mm_txt}"
    )


def _parse_sec03_key(key: str) -> tuple[str, str]:
    # formato atteso: sec03|user|cmd_base (ma cmd può contenere '|', quindi join)
    parts = key.split("|")
    user = parts[1] if len(parts) > 1 else "?"
    cmd = "|".join(parts[2:]) if len(parts) > 2 else "?"
    return user, cmd


class ArgusApp(App):
    """
    TUI v1 (polished):
    - Dashboard e Minimal (V)
    - Start/Stop (S/X) -> chiama argus start/stop
    - Overlay "ATTIVI ORA" se CRITICAL recenti
    - Sezioni: Sicurezza oggi + SEC-03 first-seen oggi + SEC-04 first-seen oggi + Feed
    - Trust (T): allowlist ultimo SEC-04
    """

    CSS = """
    Screen { padding: 1 2; }
    #hdr { height: 3; }
    #body { height: 1fr; padding-top: 1; }
    """

    view_mode = reactive("dashboard")

    BINDINGS = [
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("v", "toggle_view", "Vista"),
        ("t", "trust_last_sec04", "Trust"),
        ("m", "maintenance_30", "Maint 30m"),
        ("u", "mute_10", "Mute 10m"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="hdr")
        yield Static("", id="body")
        yield Footer()

    def on_mount(self) -> None:
        db.init_db()
        self.set_interval(1.0, self._refresh)

    # --- Actions (no demo) ---
    def action_start_monitor(self) -> None:
        try:
            subprocess.run(["argus", "start"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Start richiesto dalla TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Start: errore ({e!r})", entity="tui")
        self._refresh()

    def action_stop_monitor(self) -> None:
        try:
            subprocess.run(["argus", "stop"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Stop richiesto dalla TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Stop: errore ({e!r})", entity="tui")
        self._refresh()

    def action_toggle_view(self) -> None:
        self.view_mode = "minimal" if self.view_mode == "dashboard" else "dashboard"

    def action_maintenance_30(self) -> None:
        try:
            subprocess.run(["argus", "maintenance", "30m"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Maintenance 30m attivata dalla TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Maintenance: errore ({e!r})", entity="tui")
        self._refresh()

    def action_mute_10(self) -> None:
        try:
            subprocess.run(["argus", "mute", "10m"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Mute popup 10m attivato dalla TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Mute: errore ({e!r})", entity="tui")
        self._refresh()

    def action_trust_last_sec04(self) -> None:
        rows = db.list_first_seen(prefix="sec04|", since_ts=0, limit=50)
        if not rows:
            db.add_event(code="SYS", severity="INFO", message="Trust: nessun SEC-04 da trusted.", entity="tui")
            self._refresh()
            return

        row = max(rows, key=lambda r: int(r.get("first_ts", 0)))
        key = row.get("key", "")
        parts = key.split("|")
        if len(parts) < 5:
            db.add_event(code="SYS", severity="WARNING", message=f"Trust: key non valida: {key}", entity="tui")
            self._refresh()
            return

        proc = parts[1]
        try:
            port = int(parts[2])
        except Exception:
            port = -1
        bind = parts[4]

        _, msg = add_sec04_trust(proc, port, bind)
        db.add_event(code="SYS", severity="INFO", message=f"Trust SEC-04: {msg}", entity="tui")
        self._refresh()

    # --- UI refresh ---
    def _refresh(self) -> None:
        hdr = self.query_one("#hdr", Static)
        body = self.query_one("#body", Static)

        now = int(time.time())
        since_10m = now - 600
        midnight = _midnight_ts()

        all_recent = db.list_events(limit=300)
        last_10m = [e for e in all_recent if int(e.get("ts", 0)) >= since_10m]

        state = _global_state(last_10m)
        threat = _score(last_10m, "sec")
        health = _score(last_10m, "hea")

        # placeholder finché non implementiamo HEA-01/03
        temp = "--°C"
        disk = "--%"

        run = _status_runstop()
        hdr.update(_fmt_kpi_line(state, threat, health, temp, disk, run))

        # overlay CRITICAL (ultimi 10 minuti)
        crit_now = [e for e in last_10m if (e.get("severity") or "").upper() == "CRITICAL"]
        crit_now = sorted(crit_now, key=lambda x: int(x["ts"]), reverse=True)[:3]

        # contatori eventi SEC oggi
        counts_today: Dict[str, int] = {}
        for e in all_recent:
            if int(e.get("ts", 0)) < midnight:
                continue
            code = (e.get("code") or "")
            if _is_sec(code):
                counts_today[code] = counts_today.get(code, 0) + 1

        # first_seen: SEC-03 e SEC-04 oggi
        sec03_today = db.list_first_seen(prefix="sec03|", since_ts=midnight, limit=5)
        sec04_today = db.list_first_seen(prefix="sec04|", since_ts=midnight, limit=5)

        lines: List[str] = []

        if self.view_mode == "dashboard":
            if crit_now:
                lines.append("[bold red]ATTIVI ORA[/bold red] (CRITICAL ultimi 10 min)")
                for e in crit_now:
                    lines.append("  " + _fmt_event_line(e))
                lines.append("")

            lines.append("[bold]Sicurezza (oggi)[/bold]")
            if not counts_today:
                lines.append("  (nessun evento SEC oggi)")
            else:
                for code in ["SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-05"]:
                    if code in counts_today:
                        lines.append(f"  {CODE_ICON.get(code,'•')} [dim]{code}[/dim]  x{counts_today[code]}")
            lines.append("")

            lines.append("[bold]SEC-03 — Sudo insoliti visti oggi[/bold] (first-seen)")
            if not sec03_today:
                lines.append("  (nessuna novità oggi)")
            else:
                for row in sec03_today:
                    t = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                    user, cmd = _parse_sec03_key(row.get("key", ""))
                    cnt = int(row.get("count", 1))
                    cmd_s = cmd if len(cmd) <= 70 else cmd[:67] + "..."
                    lines.append(f"  {t}  🧨  [bold]{user}[/bold]  {cmd_s}  (x{cnt})")

            lines.append("")
            lines.append("[bold]SEC-04 — Nuove porte/servizi visti oggi[/bold]")
            if not sec04_today:
                lines.append("  (nessuna novità oggi)")
            else:
                for row in sec04_today:
                    t = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                    key = row.get("key", "")
                    parts = key.split("|")
                    proc = parts[1] if len(parts) > 1 else "?"
                    port = parts[2] if len(parts) > 2 else "?"
                    proto = parts[3] if len(parts) > 3 else "?"
                    bind = parts[4] if len(parts) > 4 else "?"
                    cnt = int(row.get("count", 1))
                    lines.append(f"  {t}  👂🌐  {proc}  {proto}/{port}  [{bind}] (x{cnt})")

            lines.append("")
            lines.append("[bold]Feed eventi (ultimi 10)[/bold]  (V = Minimal)")
        else:
            lines.append("[bold]Feed eventi (ultimi 10)[/bold]  (V = Dashboard)")

        feed = all_recent[:10]
        if not feed:
            lines.append("  (nessun evento nel DB)")
        else:
            for e in feed:
                lines.append(_fmt_event_line(e))

        body.update("\n".join(lines))
