from __future__ import annotations

from argus.trust import add_sec04_trust
from ipaddress import ip_address
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


def start_of_today_ts() -> int:
    now = datetime.now()  # timezone locale della macchina
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(midnight.timestamp())


def parse_sec03_key(key: str):
    """
    key salvata come: sec03|user|runas|cmd_norm
    """
    parts = key.split("|", 3)
    if len(parts) < 4:
        return ("?", "?", key)
    _, user, runas, cmd = parts
    return (user, runas, cmd)

def parse_sec04_key(key: str):
    """
    key salvata come: sec04|proc|port|proto|bind
    """
    parts = key.split("|")
    if len(parts) < 5:
        return ("?", "?", "?", "?")
    return (parts[1], parts[2], parts[3], parts[4])



def sec04_exposure(host: str):
    """
    Ritorna (icon, scope, severity) in base a dove è in ascolto la porta.
    """
    h = (host or "").strip().lower()

    # wildcard / tutte le interfacce
    if h in ("*", "0.0.0.0", "::"):
        return ("🌍", "PUBLIC", "CRITICAL")

    # loopback
    if h in ("127.0.0.1", "::1", "localhost"):
        return ("🔒", "LOCAL", "INFO")

    # ip reale
    try:
        ip = ip_address(host)
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            return ("🏠", "LAN", "WARNING")
        return ("🌍", "PUBLIC", "CRITICAL")
    except Exception:
        # non parsabile: trattiamolo come LAN prudente
        return ("🏠", "LAN?", "WARNING")


class DashboardPanel(Static):
    """Dashboard testuale: runtime + feed ultimi eventi + novità SEC-03 (da SQLite)."""

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

        # SEC-03: first-seen di oggi
        since = start_of_today_ts()
        sec03_new = db.list_first_seen(prefix="sec03|", since_ts=since, limit=5)
        sec03_total_today = len(db.list_first_seen(prefix="sec03|", since_ts=since, limit=9999))

        lines = []
        lines.append("👁 ARGUS — Dashboard (SQLite)")
        lines.append("")
        lines.append(f"GLOBAL: {gstatus} | STATE: {state} | MUTE: {mute_txt} | MAINT: {maint_txt}")
        lines.append("")
        # SEC-04: nuove porte in ascolto (first-seen di oggi)
        sec04_new = db.list_first_seen(prefix="sec04|", since_ts=since, limit=5)
        sec04_total_today = len(db.list_first_seen(prefix="sec04|", since_ts=since, limit=9999))

        lines.append("")
        lines.append(f"SEC-04 — Nuove porte/servizi visti oggi: {sec04_total_today}")

        if not sec04_new:
            lines.append("  (nessuna novità oggi)")
        else:
            sensitive = {22, 23, 3389, 5900, 445, 139, 3306, 5432, 6379, 9200}
            for row in sec04_new:
                first_ts = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                proc, port_s, proto, bind = parse_sec04_key(row["key"])
                try:
                    port = int(port_s)
                except Exception:
                    port = -1

                if bind.upper() == "LOCAL":
                    icon, sev = "🔒", "INFO"
                elif bind.upper() == "LAN":
                    icon, sev = "🏠", "WARNING"
                else:
                    icon = "🌍"
                    sev = "CRITICAL" if port in sensitive else "WARNING"

                count = int(row.get("count", 1))
                lines.append(f"  {first_ts}  👂🌐 {icon} {sev:<8} {proc}  {proto}/{port}  [{bind}]  (x{count})")


        # SEC-05: modifiche file importanti (oggi) dal DB events
        ev_recent = db.list_events(limit=200)
        sec05_today = [
            e for e in ev_recent
            if e.get("code") == "SEC-05" and int(e.get("ts", 0)) >= since
        ]
        sec05_today.sort(key=lambda x: int(x.get("ts", 0)), reverse=True)

        lines.append("")
        lines.append(f"SEC-05 — File importanti modificati oggi: {len(sec05_today)}")

        if not sec05_today:
            lines.append("  (nessuna modifica rilevata oggi)")
        else:
            for e in sec05_today[:5]:
                ts = datetime.fromtimestamp(int(e["ts"])).strftime("%H:%M:%S")
                sev = (e.get("severity") or "").upper()
                icon = "🧬📄"
                sev_icon = "ℹ️" if sev == "INFO" else ("⚠️" if sev == "WARNING" else "❗")
                msg = (e.get("message") or "").strip()
                if len(msg) > 80:
                    msg = msg[:77] + "..."
                lines.append(f"  {ts}  {icon}{sev_icon} {msg}")


        # Eventi
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
        lines.append(f"SEC-03 — Nuovi comandi sudo visti oggi: {sec03_total_today}")

        if not sec03_new:
            lines.append("  (nessuna novità oggi)")
        else:
            for row in sec03_new:
                first_ts = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                user, runas, cmd = parse_sec03_key(row["key"])
                count = int(row.get("count", 1))
                short = cmd.strip()
                if len(short) > 80:
                    short = short[:77] + "..."
                lines.append(f"  {first_ts}  {user}->{runas}  {short}  (x{count})")

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
        ("t", "trust_last_sec04", "Trust"),

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

    def action_trust_last_sec04(self) -> None:
        # Prendiamo il last first_seen SEC-04 (non serve selezione per v1)
        rows = db.list_first_seen(prefix="sec04|", since_ts=0, limit=1)
        if not rows:
            db.add_event(code="SYS", severity="INFO", message="Trust: nessun SEC-04 da trusted.", entity="tui")
            self._refresh()
            return

        key = rows[0]["key"]
        proc, port_s, proto, bind = parse_sec04_key(key)
        try:
            port = int(port_s)
        except Exception:
            port = -1

        added, msg = add_sec04_trust(proc, port, bind)
        db.add_event(code="SYS", severity="INFO", message=f"Trust SEC-04: {msg}", entity="tui")
        self._refresh()

