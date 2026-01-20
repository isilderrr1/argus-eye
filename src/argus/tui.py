from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
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

    msg_short = msg if len(msg) <= 95 else (msg[:92] + "...")
    return f"{ts}  {sev_i} {sev:<8} {icon} {code}  {msg_short}"


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
        f"👁 ARGUS | {state} | Threat {threat}/100 | Health {health}/100 | "
        f"🌡 {temp} | 💽 {disk} | 🔔 CRIT | {run}{mm_txt}"
    )


def _parse_sec03_key(key: str) -> tuple[str, str]:
    parts = key.split("|")
    user = parts[1] if len(parts) > 1 else "?"
    cmd = "|".join(parts[2:]) if len(parts) > 2 else "?"
    return user, cmd


def _splash_text() -> str:
    # Rich markup (Textual)
    return "\n".join(
        [
            "[bold green]┌──────────────────────────────────────────────────────────────────────┐[/bold green]",
            "[bold green]│  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗                          │[/bold green]",
            "[bold green]│ ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝                          │[/bold green]",
            "[bold green]│ ███████║██████╔╝██║  ███╗██║   ██║███████╗                          │[/bold green]",
            "[bold green]│ ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║                          │[/bold green]",
            "[bold green]│ ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║                          │[/bold green]",
            "[bold green]│ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝                          │[/bold green]",
            "[bold green]└──────────────────────────────────────────────────────────────────────┘[/bold green]",
            "",
            "[green]        .-''''-.                       [/green]",
            "[green]     .-'  _  _  '-.                    [/green]",
            "[green]    /    (o)(o)    \\                   [/green]",
            "[green]   |      .--.      |   [bold]Argus watches. You decide.[/bold][/green]",
            "[green]    \\    (____)    /                    [/green]",
            "[green]     '-.        .-'                     [/green]",
            "[green]        '-.__.-'                        [/green]",
            "",
            "[bold]What is ARGUS?[/bold]",
            "ARGUS is a lightweight Linux monitor for home desktops.",
            "It watches [bold]security[/bold] and [bold]system health[/bold] and keeps noise low:",
            "  • Popups only for [bold red]CRITICAL[/bold red] events",
            "  • Everything else goes to the feed + reports",
            "",
            "[bold]Security modules[/bold] (v1):",
            "  • SSH brute force (SEC-01) / success-after-fail (SEC-02)",
            "  • Unusual sudo (SEC-03) / new listening ports (SEC-04) / file integrity (SEC-05)",
            "",
            "[bold]Reports[/bold]:",
            "  • Markdown + JSON are saved under [dim]~/.local/share/argus/reports/[/dim]",
            "",
            "[bold]Quick keys[/bold]:",
            "  [bold]Enter[/bold] Continue to Dashboard",
            "  [bold]S[/bold] Start   [bold]X[/bold] Stop   [bold]M[/bold] Maintenance 30m   [bold]U[/bold] Mute 10m   [bold]Q[/bold] Quit",
            "",
            "[dim]Tip: if you can't read /var/log/auth.log on Ubuntu, add yourself to group 'adm' and relogin.[/dim]",
        ]
    )


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

    #splash { height: 1fr; border: round $surface; }
    #splash_text { padding: 1 2; }

    #app { height: 1fr; }
    #hdr { height: 3; }
    #overlay { height: auto; }
    #summary { height: auto; padding: 1 0; }

    #main { height: 1fr; }
    #feed { width: 1fr; border: round $surface; }

    #detail_box { width: 1fr; height: 1fr; border: round $surface; }
    #detail_text { padding: 1 2; }

    #footerbar { height: 1; padding: 0 1; background: $surface; color: $text; }
    .hidden { display: none; }
    """

    ui_mode = reactive("splash")        # splash|main
    view_mode = reactive("dashboard")   # dashboard|minimal
    show_details = reactive(True)

    _selected: Optional[Selected] = None
    _last_feed_sig: Tuple[int, int] = (-1, -1)  # (top_id, count)

    # Report override: quando apri un report con Enter, lo blocchiamo qui per non farlo sovrascrivere dal refresh.
    _detail_override_text: Optional[str] = None
    _detail_override_event_id: Optional[int] = None

    BINDINGS = [
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("d", "toggle_details", "Dettagli"),
        ("v", "toggle_view", "Vista"),
        ("t", "trust_selected", "Trust"),
        ("k", "clear_events", "Pulisci"),
        ("m", "maintenance_30", "Maint 30m"),
        ("u", "mute_10", "Mute 10m"),
        ("enter", "open_selected", "Continue/Open"),
        ("escape", "close_report", "Back"),
        ("q", "quit", "Quit"),
        ("up", "cursor_up", ""),
        ("down", "cursor_down", ""),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="splash"):
            yield Static(_splash_text(), id="splash_text")

        with Container(id="app"):
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
        self._apply_global_visibility()
        self._refresh()

    # ----- splash/global visibility -----
    def action_continue(self) -> None:
        self.ui_mode = "main"
        self._apply_global_visibility()
        self._refresh()
        self.query_one("#feed", ListView).focus()

    def _apply_global_visibility(self) -> None:
        splash = self.query_one("#splash", VerticalScroll)
        app = self.query_one("#app", Container)

        if self.ui_mode == "splash":
            splash.remove_class("hidden")
            app.add_class("hidden")
            return

        splash.add_class("hidden")
        app.remove_class("hidden")
        self._apply_visibility()

    # ----- view modes -----
    def action_toggle_view(self) -> None:
        if self.ui_mode != "main":
            return
        self.view_mode = "minimal" if self.view_mode == "dashboard" else "dashboard"
        self._apply_visibility()

    def action_toggle_details(self) -> None:
        if self.ui_mode != "main":
            return
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
    def action_close_report(self) -> None:
        """Esc: esce dalla vista report e torna ai dettagli evento."""
        if self._detail_override_text is None:
            return
        self._detail_override_text = None
        self._detail_override_event_id = None
        self._update_detail()

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
        if self.ui_mode != "main":
            return

        lv = self.query_one("#feed", ListView)
        overlay = self.query_one("#overlay", Static)
        summary = self.query_one("#summary", Static)
        detail_text = self.query_one("#detail_text", Static)

        lv.clear()
        overlay.update("")
        summary.update("")
        detail_text.update("")
        self._selected = None
        self._last_feed_sig = (-1, -1)

        self._detail_override_text = None
        self._detail_override_event_id = None

        try:
            db.clear_all_events()
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Clear events failed: {e!r}", entity="tui")

        self._refresh()

    def action_cursor_up(self) -> None:
        if self.ui_mode != "main":
            return
        lv = self.query_one("#feed", ListView)
        if not lv.children:
            lv.index = None
            return
        if lv.index is None:
            lv.index = 0
        else:
            lv.index = max(0, lv.index - 1)

    def action_cursor_down(self) -> None:
        if self.ui_mode != "main":
            return
        lv = self.query_one("#feed", ListView)
        if not lv.children:
            lv.index = None
            return
        if lv.index is None:
            lv.index = 0
        else:
            lv.index = min(len(lv.children) - 1, lv.index + 1)

    def action_open_selected(self) -> None:
        # In splash: Enter = continue
        if self.ui_mode != "main":
            self.action_continue()
            return

        detail_text = self.query_one("#detail_text", Static)
        if not self._selected:
            return

        e = self._selected.event
        eid = int(e.get("id") or 0)
        md_path = (e.get("report_md_path") or "").strip()
        if not md_path:
            db.add_event(code="SYS", severity="INFO", message="Report: nessun report associato a questo evento.", entity="tui")
            self._refresh()
            return

        p = Path(md_path)
        if not p.exists():
            db.add_event(code="SYS", severity="WARNING", message=f"Report non trovato su disco: {md_path}", entity="tui")
            self._refresh()
            return

        try:
            txt = p.read_text(encoding="utf-8")
        except Exception as ex:
            txt = f"Errore lettura report: {ex!r}\nPath: {md_path}"

        self._detail_override_text = txt
        self._detail_override_event_id = eid
        detail_text.update(txt)

    def action_trust_selected(self) -> None:
        if self.ui_mode != "main":
            return

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
        if self.ui_mode != "main":
            return

        item = message.item
        if isinstance(item, EventRow):
            new_id = int(item.event.get("id") or 0)
            if self._detail_override_event_id is not None and self._detail_override_event_id != new_id:
                self._detail_override_text = None
                self._detail_override_event_id = None

            self._selected = Selected(event=item.event)
            self._update_detail()

    # ----- detail panel -----
    def _update_detail(self) -> None:
        if self.ui_mode != "main":
            return

        detail_text = self.query_one("#detail_text", Static)
        if not self._selected:
            detail_text.update("")
            return

        e = self._selected.event
        eid = int(e.get("id") or 0)

        if self._detail_override_text is not None and self._detail_override_event_id == eid:
            detail_text.update(self._detail_override_text)
            return

        ts = datetime.fromtimestamp(int(e["ts"])).strftime("%Y-%m-%d %H:%M:%S")
        sev = (e.get("severity") or "INFO").upper()
        code = (e.get("code") or "")
        ent = (e.get("entity") or "")
        msg = (e.get("message") or "").strip()

        advice = ADVICE.get(code, [])
        advice_txt = "\n".join([f"  • {a}" for a in advice]) if advice else "  • (azioni consigliate: in arrivo)"
        has_report = "SI" if (e.get("report_md_path") or "").strip() else "NO"

        detail_text.update(
            "\n".join(
                [
                    f"{code} ({sev})",
                    f"{ts}",
                    "",
                    "Cosa è successo",
                    f"  {msg}",
                    "",
                    "Entità",
                    f"  {ent if ent else '(n/a)'}",
                    "",
                    "Cosa fare ora",
                    f"{advice_txt}",
                    "",
                    f"Report associato: {has_report}  (Enter apre, Esc torna indietro)",
                ]
            )
        )

    # ----- footer -----
    def _update_footerbar(self) -> None:
        if self.ui_mode != "main":
            return

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
            f"S Start  X Stop  D Dettagli  V Vista  T Trust  K Pulisci  M Maint  U Mute  Enter Report  Esc Back  Q Quit"
            f"    {run} | {view} | {det}{flags_txt}"
        )

    # ----- refresh loop -----
    def _refresh(self) -> None:
        db.init_db()

        # In splash non serve aggiornare UI “main”, ma possiamo lasciare il loop attivo (non rompe).
        if self.ui_mode != "main":
            return

        hdr = self.query_one("#hdr", Static)
        overlay = self.query_one("#overlay", Static)
        summary = self.query_one("#summary", Static)
        lv = self.query_one("#feed", ListView)

        now = int(time.time())
        since_10m = now - 600
        midnight = _midnight_ts()

        all_recent = db.list_events(limit=500)
        visible = [e for e in all_recent if (e.get("code") or "") != "SYS"]

        top_id = int(visible[0]["id"]) if visible else 0
        feed_sig = (top_id, len(visible))

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
            lines = ["ATTIVI ORA"]
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
            out.append("Sicurezza (oggi)")
            any_sec = False
            for c in ["SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-05"]:
                if c in counts_today:
                    any_sec = True
                    out.append(f"  {CODE_ICON.get(c,'•')} {c}  x{counts_today[c]}")
            if not any_sec:
                out.append("  (nessun evento SEC oggi)")

            out.append("")
            out.append("SEC-03 — Sudo insoliti visti oggi (first-seen)")
            if not sec03_today:
                out.append("  (nessuna novità oggi)")
            else:
                for row in sec03_today:
                    t = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                    user, cmd = _parse_sec03_key(row.get("key", ""))
                    cnt = int(row.get("count", 1))
                    cmd_s = cmd if len(cmd) <= 70 else cmd[:67] + "..."
                    out.append(f"  {t}  🧨  {user}  {cmd_s}  (x{cnt})")

            out.append("")
            out.append("SEC-04 — Nuove porte/servizi visti oggi (first-seen)")
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
