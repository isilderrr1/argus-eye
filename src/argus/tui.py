from __future__ import annotations

import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Static, ListView, ListItem, Label

from argus import db
from argus.trust import add_sec04_trust


CODE_ICON: Dict[str, str] = {
    "SEC-01": "🚫🔑",
    "SEC-02": "🛡️🔑",
    "SEC-03": "🧨",
    "SEC-04": "👂🌐",
    "SEC-05": "🧬📄",
    "HEA-01": "🌡",
    "HEA-02": "🔥",
    "HEA-03": "💽",
    "HEA-04": "🔁",
    "HEA-05": "🧱",
    "SYS": "🛈",
}

SEV_ICON = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "❗"}
SEV_STYLE = {"INFO": "cyan", "WARNING": "yellow", "CRITICAL": "red"}

RE_SEC04 = re.compile(
    r"^(?:Nuovo servizio locale|Nuovo servizio in rete|Porta esposta):\s*"
    r"(?P<proc>\S+)\s+su\s+(?P<addr>[^:]+):(?P<port>\d+)/(?P<proto>\w+).*\[(?P<bind>LOCAL|LAN|GLOBAL)\]",
    re.IGNORECASE,
)

ADVICE: Dict[str, List[str]] = {
    "SEC-01": [
        "Se non sei tu: cambia password e disabilita SSH se non serve.",
        "Blocca l’IP (ufw/nftables) e verifica utenti/chiavi SSH.",
        "Controlla report/log per capire username provati e frequenza.",
    ],
    "SEC-02": [
        "Verifica se l’accesso era tuo (IP, orario, user).",
        "Se sospetto: cambia password e chiudi le sessioni attive.",
        "Controlla comandi recenti e attività sudo (SEC-03).",
    ],
    "SEC-03": [
        "Se non sei tu: cambia password e verifica account/local users.",
        "Controlla cosa ha fatto quel comando e cosa è cambiato nel sistema.",
        "Se high-risk: verifica /etc/passwd, sudoers, cron, systemctl, ecc.",
    ],
    "SEC-04": [
        "Verifica se il servizio è voluto (programma e porta).",
        "Se non serve: chiudi porta o disabilita il servizio.",
        "Se è voluto: premi T per Trust (allowlist) e riduci rumore.",
    ],
    "SEC-05": [
        "Se non sei tu: verifica subito cosa è cambiato nel file.",
        "Controlla aggiornamenti/maintenance e attività sudo correlate (SEC-03).",
        "Ripristina configurazione sicura e ruota credenziali se necessario.",
    ],
}


def _db_path() -> Path:
    if hasattr(db, "get_db_path"):
        try:
            return Path(db.get_db_path())  # type: ignore[attr-defined]
        except Exception:
            pass
    return Path.home() / ".local/share/argus/argus.db"


def _midnight_ts() -> int:
    now = datetime.now()
    mid = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(mid.timestamp())


def _global_state(recent: List[dict]) -> str:
    if any((e.get("severity") or "").upper() == "CRITICAL" for e in recent):
        return "ALERT"
    if any((e.get("severity") or "").upper() == "WARNING" for e in recent):
        return "WATCHING"
    return "CALM"


def _score(recent: List[dict], prefix: str) -> int:
    s = 0
    for e in recent:
        code = (e.get("code") or "")
        if not code.startswith(prefix):
            continue
        sev = (e.get("severity") or "").upper()
        if sev == "CRITICAL":
            s += 30
        elif sev == "WARNING":
            s += 10
    return max(0, min(100, s))


def _status_runstop() -> str:
    try:
        r = subprocess.run(["argus", "status"], capture_output=True, text=True, timeout=1.5)
        out = (r.stdout or "").strip().splitlines()
        if out:
            return out[0].strip()
    except Exception:
        pass
    return "UNKNOWN"


def _flag_badge(flag_name: str) -> str:
    return flag_name.upper() if db.get_flag(flag_name) else ""


def _fmt_event_line(e: dict) -> str:
    ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
    sev = (e.get("severity") or "INFO").upper()
    code = (e.get("code") or "")
    msg = (e.get("message") or "").strip()

    icon = CODE_ICON.get(code, "•")
    sev_i = SEV_ICON.get(sev, "•")
    color = SEV_STYLE.get(sev, "white")

    msg_short = msg if len(msg) <= 95 else (msg[:92] + "...")
    return f"{ts}  [{color}]{sev_i} {sev:<8}[/{color}] {icon} [dim]{code}[/dim]  {msg_short}"


def _fmt_header(state: str, threat: int, health: int, temp: str, disk: str, run: str) -> str:
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
    parts = key.split("|")
    user = parts[1] if len(parts) > 1 else "?"
    cmd = "|".join(parts[2:]) if len(parts) > 2 else "?"
    return user, cmd


@dataclass
class Selected:
    event: dict


class EventRow(ListItem):
    def __init__(self, e: dict) -> None:
        super().__init__(Label(_fmt_event_line(e)))
        self.event = e


class ArgusApp(App):
    CSS = """
    Screen { padding: 1 2; }

    #hdr { height: 3; }
    #overlay { height: auto; }
    #summary { height: auto; padding: 1 0; }

    #main { height: 1fr; }
    #feed { width: 1fr; border: round $surface; }

    /* Dettagli: ora scrollabile */
    #detail_box { width: 1fr; height: 1fr; border: round $surface; }
    #detail_text { padding: 1 2; }

    #footerbar { height: 1; padding: 0 1; background: $surface; color: $text; }
    .hidden { display: none; }
    """

    view_mode = reactive("dashboard")   # dashboard|minimal
    show_details = reactive(True)

    _selected: Optional[Selected] = None
    _last_feed_sig: Tuple[int, int] = (-1, -1)  # (top_ts, count)

    BINDINGS = [
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("d", "toggle_details", "Dettagli"),
        ("v", "toggle_view", "Vista"),
        ("t", "trust_selected", "Trust"),
        ("k", "clear_events", "Pulisci"),
        ("m", "maintenance_30", "Maint 30m"),
        ("u", "mute_10", "Mute 10m"),
        ("enter", "open_selected", "Apri"),
        ("q", "quit", "Quit"),
        ("up", "cursor_up", ""),
        ("down", "cursor_down", ""),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="hdr")
        yield Static("", id="overlay")
        yield Static("", id="summary")
        with Horizontal(id="main"):
            yield ListView(id="feed")
            with VerticalScroll(id="detail_box"):
                yield Static("", id="detail_text")
        yield Static("", id="footerbar")

    def on_mount(self) -> None:
        db.init_db()
        self.set_interval(1.0, self._refresh)
        self._refresh()
        self.query_one("#feed", ListView).focus()

    # ----- view modes -----
    def action_toggle_view(self) -> None:
        self.view_mode = "minimal" if self.view_mode == "dashboard" else "dashboard"
        self._apply_visibility()

    def action_toggle_details(self) -> None:
        self.show_details = not self.show_details
        self._apply_visibility()

    def _apply_visibility(self) -> None:
        summary = self.query_one("#summary", Static)
        detail_box = self.query_one("#detail_box", VerticalScroll)

        if self.view_mode == "minimal":
            summary.add_class("hidden")
            detail_box.add_class("hidden")
            return

        summary.remove_class("hidden")
        if self.show_details and self.size.width >= 100:
            detail_box.remove_class("hidden")
        else:
            detail_box.add_class("hidden")

    # ----- actions -----
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

    def action_clear_events(self) -> None:
        """K: pulisce eventi (DB + UI)."""
        lv = self.query_one("#feed", ListView)
        overlay = self.query_one("#overlay", Static)
        summary = self.query_one("#summary", Static)
        detail_text = self.query_one("#detail_text", Static)

        # UI subito
        lv.clear()
        overlay.update("")
        summary.update("")
        detail_text.update("")
        self._selected = None
        self._last_feed_sig = (-1, -1)

        # DB
        try:
            path = _db_path()
            with sqlite3.connect(path) as conn:
                conn.execute("PRAGMA busy_timeout=2000;")
                conn.execute("DELETE FROM events;")
                conn.commit()
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Clear events failed: {e!r}", entity="tui")

        self._refresh()

    def action_cursor_up(self) -> None:
        lv = self.query_one("#feed", ListView)
        if lv.index is None:
            lv.index = 0
        else:
            lv.index = max(0, lv.index - 1)

    def action_cursor_down(self) -> None:
        lv = self.query_one("#feed", ListView)
        if lv.index is None:
            lv.index = 0
        else:
            lv.index = min(max(0, len(lv.children) - 1), lv.index + 1)

    def action_open_selected(self) -> None:
        if not self._selected:
            return
        e = self._selected.event
        db.add_event(code="SYS", severity="INFO",
                     message=f"Apri: report non ancora implementato (selezionato {e.get('code')}).",
                     entity="tui")
        self._refresh()

    def action_trust_selected(self) -> None:
        if not self._selected:
            db.add_event(code="SYS", severity="INFO", message="Trust: seleziona prima un evento.", entity="tui")
            self._refresh()
            return

        e = self._selected.event
        code = (e.get("code") or "")
        msg = (e.get("message") or "")

        if code != "SEC-04":
            db.add_event(code="SYS", severity="INFO", message="Trust: valido solo su SEC-04.", entity="tui")
            self._refresh()
            return

        m = RE_SEC04.search(msg)
        if not m:
            db.add_event(code="SYS", severity="WARNING", message="Trust: parse proc/porta/bind fallito.", entity="tui")
            self._refresh()
            return

        proc = m.group("proc")
        port = int(m.group("port"))
        bind = m.group("bind").upper()

        _, out = add_sec04_trust(proc, port, bind)
        db.add_event(code="SYS", severity="INFO", message=f"Trust SEC-04: {out}", entity="tui")
        self._refresh()

    # ----- listview highlight -----
    def on_list_view_highlighted(self, message: ListView.Highlighted) -> None:
        item = message.item
        if isinstance(item, EventRow):
            self._selected = Selected(event=item.event)
            self._update_detail()

    # ----- detail panel -----
    def _update_detail(self) -> None:
        detail_text = self.query_one("#detail_text", Static)
        if not self._selected:
            detail_text.update("")
            return

        e = self._selected.event
        ts = datetime.fromtimestamp(int(e["ts"])).strftime("%Y-%m-%d %H:%M:%S")
        sev = (e.get("severity") or "INFO").upper()
        code = (e.get("code") or "")
        ent = (e.get("entity") or "")
        msg = (e.get("message") or "").strip()

        icon = CODE_ICON.get(code, "•")
        sev_i = SEV_ICON.get(sev, "•")
        color = SEV_STYLE.get(sev, "white")

        advice = ADVICE.get(code, [])
        advice_txt = "\n".join([f"  • {a}" for a in advice]) if advice else "  • (azioni consigliate: in arrivo)"

        detail_text.update(
            "\n".join(
                [
                    f"[bold]{icon} {code}[/bold]  [{color}]{sev_i} {sev}[/{color}]",
                    f"[dim]{ts}[/dim]",
                    "",
                    f"[bold]Cosa è successo[/bold]\n  {msg}",
                    "",
                    f"[bold]Entità[/bold]\n  {ent if ent else '(n/a)'}",
                    "",
                    f"[bold]Cosa fare ora[/bold]\n{advice_txt}",
                    "",
                    "[dim]Suggerimento: se il testo è lungo, scorri nel pannello Dettagli.[/dim]",
                ]
            )
        )

    # ----- footer -----
    def _update_footerbar(self) -> None:
        footer = self.query_one("#footerbar", Static)
        view = "Dash" if self.view_mode == "dashboard" else "Min"
        det = "Det ON" if (self.view_mode == "dashboard" and self.show_details and self.size.width >= 100) else "Det OFF"
        run = _status_runstop()

        flags = []
        if _flag_badge("mute"):
            flags.append("MUTE")
        if _flag_badge("maintenance"):
            flags.append("MAINT")
        flags_txt = (" | " + "/".join(flags)) if flags else ""

        footer.update(
            f"[bold]S[/bold] Start  [bold]X[/bold] Stop  [bold]D[/bold] Dettagli  [bold]V[/bold] Vista  "
            f"[bold]T[/bold] Trust  [bold]K[/bold] Pulisci  [bold]M[/bold] Maint  [bold]U[/bold] Mute  [bold]Q[/bold] Quit"
            f"    [dim]{run} | {view} | {det}{flags_txt}[/dim]"
        )

    # ----- refresh loop -----
    def _refresh(self) -> None:
        db.init_db()

        hdr = self.query_one("#hdr", Static)
        overlay = self.query_one("#overlay", Static)
        summary = self.query_one("#summary", Static)
        lv = self.query_one("#feed", ListView)

        now = int(time.time())
        since_10m = now - 600
        midnight = _midnight_ts()

        all_recent = db.list_events(limit=500)
        visible = [e for e in all_recent if (e.get("code") or "") != "SYS"]  # hide SYS
        top_ts = int(visible[0]["ts"]) if visible else 0
        feed_sig = (top_ts, len(visible))

        last_10m = [e for e in visible if int(e.get("ts", 0)) >= since_10m]
        state = _global_state(last_10m)
        threat = _score(last_10m, "SEC-")
        health = _score(last_10m, "HEA-")

        temp = "--°C"
        disk = "--%"

        run = _status_runstop()
        hdr.update(_fmt_header(state, threat, health, temp, disk, run))

        crit_now = [e for e in last_10m if (e.get("severity") or "").upper() == "CRITICAL"]
        crit_now = sorted(crit_now, key=lambda x: int(x["ts"]), reverse=True)[:3]
        if crit_now:
            lines = ["[bold red]ATTIVI ORA[/bold red]"]
            for e in crit_now:
                lines.append("  " + _fmt_event_line(e))
            overlay.update("\n".join(lines))
        else:
            overlay.update("")

        if self.view_mode == "dashboard":
            counts_today: Dict[str, int] = {}
            for e in visible:
                if int(e.get("ts", 0)) < midnight:
                    continue
                c = (e.get("code") or "")
                if c.startswith("SEC-"):
                    counts_today[c] = counts_today.get(c, 0) + 1

            sec03_today = db.list_first_seen(prefix="sec03|", since_ts=midnight, limit=5)
            sec04_today = db.list_first_seen(prefix="sec04|", since_ts=midnight, limit=5)

            out: List[str] = []
            out.append("[bold]Sicurezza (oggi)[/bold]")
            any_sec = False
            for c in ["SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-05"]:
                if c in counts_today:
                    any_sec = True
                    out.append(f"  {CODE_ICON.get(c,'•')} [dim]{c}[/dim]  x{counts_today[c]}")
            if not any_sec:
                out.append("  (nessun evento SEC oggi)")

            out.append("")
            out.append("[bold]SEC-03 — Sudo insoliti visti oggi[/bold] (first-seen)")
            if not sec03_today:
                out.append("  (nessuna novità oggi)")
            else:
                for row in sec03_today:
                    t = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                    user, cmd = _parse_sec03_key(row.get("key", ""))
                    cnt = int(row.get("count", 1))
                    cmd_s = cmd if len(cmd) <= 70 else cmd[:67] + "..."
                    out.append(f"  {t}  🧨  [bold]{user}[/bold]  {cmd_s}  (x{cnt})")

            out.append("")
            out.append("[bold]SEC-04 — Nuove porte/servizi visti oggi[/bold] (first-seen)")
            if not sec04_today:
                out.append("  (nessuna novità oggi)")
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
                    out.append(f"  {t}  👂🌐  {proc}  {proto}/{port}  [{bind}] (x{cnt})")

            summary.update("\n".join(out))
        else:
            summary.update("")

        if feed_sig != self._last_feed_sig:
            self._last_feed_sig = feed_sig
            old_index = lv.index

            lv.clear()
            for e in visible[:20]:
                lv.append(EventRow(e))

            if len(lv.children) > 0:
                if old_index is not None:
                    lv.index = min(max(0, old_index), len(lv.children) - 1)
                else:
                    lv.index = 0
            else:
                lv.index = None
                self._selected = None

        self._apply_visibility()
        self._update_detail()
        self._update_footerbar()
