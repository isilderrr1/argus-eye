from __future__ import annotations

from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static

from argus import db


def fmt_seconds(sec: int) -> str:
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def global_status_from_events(events) -> str:
    sevs = { (e.get("severity") or "").upper() for e in events }
    if "CRITICAL" in sevs:
        return "ALERT"
    if "WARNING" in sevs:
        return "WATCHING"
    return "CALM"


class DashboardPanel(Static):
    """Dashboard testuale: runtime + feed ultimi eventi (da SQLite)."""

    def on_mount(self) -> None:
        self.refresh_all()
        self.set_interval(1.0, self.refresh_all)

    def refresh_all(self) -> None:
        db.init_db()

        # Runtime flags
        state_data = db.get_flag("monitor_state")
        state = state_data[0] if state_data else "STOPPED"

        mute_left = db.remaining_seconds("mute")
        maint_left = db.remaining_seconds("maintenance")

        mute_txt = "OFF" if mute_left is None else f"ON ({fmt_seconds(mute_left)})"
        maint_txt = "OFF" if maint_left is None else f"ON ({fmt_seconds(maint_left)})"

        # Feed eventi
        events = db.list_events(limit=10)
        gstatus = global_status_from_events(events)

        lines = []
        lines.append("👁 ARGUS — Dashboard (SQLite)")
        lines.append("")
        lines.append(f"GLOBAL: {gstatus} | STATE: {state} | MUTE: {mute_txt} | MAINT: {maint_txt}")
        lines.append("")
        lines.append("Ultimi eventi (max 10):")

        if not events:
            lines.append("  (nessun evento nel DB)")
        else:
            for e in events:
                ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
                sev = (e.get("severity") or "").upper()
                code = (e.get("code") or "")
                msg = (e.get("message") or "").strip()
                if len(msg) > 70:
                    msg = msg[:67] + "..."
                lines.append(f"  {ts}  {sev:<8} {code:<7} {msg}")

        lines.append("")
        lines.append("Shortcut:")
        lines.append("  S Start  | X Stop | U Mute 10m | M Maint 30m | E Demo SEC | H Demo HEA | K Clear events | Q Quit")

        self.update("\n".join(lines))
        self.app.sub_title = f"{gstatus} | {state} | MUTE {mute_txt} | MAINT {maint_txt}"


class ArgusApp(App):
    TITLE = "ARGUS"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("u", "mute_10m", "Mute 10m"),
        ("m", "maintenance_30m", "Maint 30m"),
        ("e", "demo_sec", "Demo SEC"),
        ("h", "demo_hea", "Demo HEA"),
        ("k", "clear_events", "Clear events"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DashboardPanel(id="dash")
        yield Footer()

    def _refresh(self) -> None:
        self.query_one(DashboardPanel).refresh_all()

    def action_start_monitor(self) -> None:
        db.set_flag("monitor_state", "RUNNING", ttl_seconds=None)
        self._refresh()

    def action_stop_monitor(self) -> None:
        db.set_flag("monitor_state", "STOPPED", ttl_seconds=None)
        self._refresh()

    def action_mute_10m(self) -> None:
        db.set_flag("mute", "1", ttl_seconds=10 * 60)
        self._refresh()

    def action_maintenance_30m(self) -> None:
        db.set_flag("maintenance", "1", ttl_seconds=30 * 60)
        self._refresh()

    def action_demo_sec(self) -> None:
        db.add_event(code="SEC-01", severity="WARNING", message="DEMO: Tentativo SSH fallito (LAN)", entity="192.168.1.50")
        self._refresh()

    def action_demo_hea(self) -> None:
        db.add_event(code="HEA-02", severity="CRITICAL", message="DEMO: Temperatura critica CPU", entity="cpu0")
        self._refresh()

    def action_clear_events(self) -> None:
        db.clear_events()
        self._refresh()
