from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static

from argus import db


def fmt_seconds(sec: int) -> str:
    """Formatta secondi in modo leggibile (es. 9m12s / 1h05m)."""
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


class StatusPanel(Static):
    """Pannello che mostra stato runtime leggendo dal DB (SQLite)."""

    def on_mount(self) -> None:
        # Aggiorna subito e poi ogni 1 secondo
        self.refresh_status()
        self.set_interval(1.0, self.refresh_status)

    def refresh_status(self) -> None:
        # Sicurezza: se DB non fosse inizializzato, lo inizializziamo
        db.init_db()

        # Stato monitor
        state_data = db.get_flag("monitor_state")
        state = state_data[0] if state_data else "STOPPED"

        # Flag temporanee con scadenza
        mute_left = db.remaining_seconds("mute")
        maint_left = db.remaining_seconds("maintenance")

        mute_txt = "OFF" if mute_left is None else f"ON ({fmt_seconds(mute_left)})"
        maint_txt = "OFF" if maint_left is None else f"ON ({fmt_seconds(maint_left)})"

        # Aggiorna testo a schermo
        self.update(
            "\n".join(
                [
                    "👁 ARGUS — Runtime status (da SQLite)",
                    "",
                    f"STATE: {state}",
                    f"MUTE: {mute_txt}",
                    f"MAINTENANCE: {maint_txt}",
                    "",
                    "Tasti rapidi:",
                    "  S = Start   X = Stop   U = Mute 10m   M = Maintenance 30m   Q = Quit",
                ]
            )
        )

        # Aggiorna anche la sottolineatura dell'header (sub_title)
        self.app.sub_title = f"{state} | MUTE {mute_txt} | MAINT {maint_txt}"


class ArgusApp(App):
    """TUI v1: mostra stato runtime leggendo dal DB e consente azioni base."""

    TITLE = "ARGUS"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("u", "mute_10m", "Mute 10m"),
        ("m", "maintenance_30m", "Maint 30m"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusPanel(id="status")
        yield Footer()

    # Azioni (scrivono nel DB): la TUI è un client dello "stato"
    def action_start_monitor(self) -> None:
        db.set_flag("monitor_state", "RUNNING", ttl_seconds=None)
        self.query_one(StatusPanel).refresh_status()

    def action_stop_monitor(self) -> None:
        db.set_flag("monitor_state", "STOPPED", ttl_seconds=None)
        self.query_one(StatusPanel).refresh_status()

    def action_mute_10m(self) -> None:
        db.set_flag("mute", "1", ttl_seconds=10 * 60)
        self.query_one(StatusPanel).refresh_status()

    def action_maintenance_30m(self) -> None:
        db.set_flag("maintenance", "1", ttl_seconds=30 * 60)
        self.query_one(StatusPanel).refresh_status()
