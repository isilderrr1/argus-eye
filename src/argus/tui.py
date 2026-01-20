from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Static, ListView, ListItem, Label

from argus import __version__ as ARGUS_VERSION
from argus import db
from argus.trust import add_sec04_trust

from argus.collectors.temperature import format_cpu_temp


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

RE_SEC04 = re.compile(
    r"^(?:Nuovo servizio locale|Nuovo servizio in rete|Porta esposta):\s*"
    r"(?P<proc>\S+)\s+su\s+(?P<addr>[^:]+):(?P<port>\d+)/(?P<proto>\w+).*\[(?P<bind>LOCAL|LAN|GLOBAL)\]",
    re.IGNORECASE,
)

ADVICE: Dict[str, List[str]] = {
    "SEC-01": [
        "If it wasn't you: change password and disable SSH if not needed.",
        "Block the IP (ufw/nftables) and review users/SSH keys.",
        "Check logs to see usernames targeted and frequency.",
    ],
    "SEC-02": [
        "Confirm if the login was yours (IP, time, user).",
        "If suspicious: change password and close active sessions.",
        "Review recent commands and sudo activity (SEC-03).",
    ],
    "SEC-03": [
        "If it wasn't you: change password and review local users.",
        "Check what that command changed on the system.",
        "High-risk: review passwd/sudoers/cron/systemctl changes.",
    ],
    "SEC-04": [
        "Confirm the service is expected (process and port).",
        "If not needed: close the port or disable the service.",
        "If expected: press T to Trust (allowlist) to reduce noise.",
    ],
    "SEC-05": [
        "If it wasn't you: verify what changed immediately.",
        "Check maintenance/updates and related sudo activity (SEC-03).",
        "Restore secure config and rotate credentials if needed.",
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
    msg_short = msg if len(msg) <= 100 else (msg[:97] + "...")
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


def _read_uptime_seconds() -> Optional[int]:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            first = f.read().strip().split()[0]
        return int(float(first))
    except Exception:
        return None


def _fmt_uptime(sec: Optional[int]) -> str:
    if sec is None:
        return "--"
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d > 0:
        return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"


def _get_lan_ip() -> str:
    try:
        r = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=1.0,
        )
        out = (r.stdout or "").strip().splitlines()
        ips: List[str] = []
        for line in out:
            parts = line.split()
            if "inet" in parts:
                i = parts.index("inet")
                ip = parts[i + 1].split("/")[0]
                ips.append(ip)

        def is_lan(ip: str) -> bool:
            return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("169.254.")

        for ip in ips:
            if is_lan(ip):
                return ip
        return ips[0] if ips else "--"
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "--"


def _logo_argus_lines() -> List[str]:
    # 7-high readable block letters: ARGUS
    A = [
        "   ███   ",
        "  █   █  ",
        " █     █ ",
        " ███████ ",
        " █     █ ",
        " █     █ ",
        " █     █ ",
    ]
    R = [
        " ██████  ",
        " █     █ ",
        " █     █ ",
        " ██████  ",
        " █   █   ",
        " █    █  ",
        " █     █ ",
    ]
    G = [
        "  ██████ ",
        " █       ",
        " █       ",
        " █  ████ ",
        " █     █ ",
        " █     █ ",
        "  █████  ",
    ]
    U = [
        " █     █ ",
        " █     █ ",
        " █     █ ",
        " █     █ ",
        " █     █ ",
        " █     █ ",
        "  █████  ",
    ]
    S = [
        "  ██████ ",
        " █       ",
        " █       ",
        "  █████  ",
        "       █ ",
        "       █ ",
        " ██████  ",
    ]

    out: List[str] = []
    for i in range(7):
        out.append(A[i] + " " + R[i] + " " + G[i] + " " + U[i] + " " + S[i])
    return out


def _splash_body_lines() -> List[str]:
    return [
        "",
        "[bold]What it is[/bold]",
        "ARGUS is a Linux desktop monitor for security + system health.",
        "It keeps the UI clean and sends desktop popups only for CRITICAL events.",
        "",
        "[bold]Controls[/bold]",
        "  Enter  -> Continue to Dashboard",
        "  Q      -> Quit",
        "",
        "[bold]Reports[/bold]",
        "  ~/.local/share/argus/reports/",
    ]


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

    /* Splash */
    #splash { height: 1fr; border: round $surface; }
    #splash_banner { height: 3; padding: 0 2; }
    #splash_matrix { height: 12; padding: 0 2; }
    #splash_body { height: 1fr; padding: 0 2; }

    /* Main app */
    #app { height: 1fr; }
    #hdr { height: 3; }
    #overlay { height: auto; }
    #summary { height: auto; padding: 1 0; }

    #main { height: 1fr; }
    #feed { width: 1fr; border: round $surface; }

    #detail_box { width: 1fr; height: 1fr; border: round $surface; }
    #detail_text { padding: 1 2; }

    #footerbar { height: 2; padding: 0 1; background: $surface; color: $text; }

    .hidden { display: none; }

    /* Responsive layout profiles */
    .wide #main { layout: horizontal; }
    .stack #main { layout: vertical; }
    .stack #feed { width: 1fr; height: 2fr; }
    .stack #detail_box { width: 1fr; height: 1fr; }
    .short #overlay { display: none; }
    .tiny #overlay { display: none; }
    .tiny #summary { display: none; }
    .tiny #detail_box { display: none; }


    /* Responsive helpers */
    .narrow #detail_box { display: none; }
    .narrow #summary { display: none; }
    .short #overlay { display: none; }
    .tiny #overlay { display: none; }
    .tiny #summary { display: none; }
    .tiny #hdr { height: 2; }

    """

    ui_mode = reactive("splash")        # splash|main
    view_mode = reactive("dashboard")   # dashboard|minimal
    show_details = reactive(True)

    _selected: Optional[Selected] = None
    _last_feed_sig: Tuple[int, int] = (-1, -1)  # (top_id, count)

    _detail_override_text: Optional[str] = None
    _detail_override_event_id: Optional[int] = None

    # splash caching (avoid rebuilding banner every frame)
    _last_banner_text: str = ""
    _last_banner_update_ts: float = 0.0

    BINDINGS = [
        ("s", "start_monitor", "Start"),
        ("x", "stop_monitor", "Stop"),
        ("d", "toggle_details", "Details"),
        ("v", "toggle_view", "View"),
        ("t", "trust_selected", "Trust"),
        ("k", "clear_events", "Clear"),
        ("m", "maintenance_30", "Maint 30m"),
        ("u", "mute_10", "Mute 10m"),
        ("q", "quit", "Quit"),
        ("up", "cursor_up", ""),
        ("down", "cursor_down", ""),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="splash"):
            yield Static("", id="splash_banner")
            yield Static("", id="splash_matrix")
            yield Static("", id="splash_body")

        with Container(id="app"):
            yield Static("", id="hdr")
            yield Static("", id="overlay")
            yield Static("", id="summary")
            with Container(id="main"):
                yield ListView(id="feed")
                with VerticalScroll(id="detail_box"):
                    yield Static("", id="detail_text")
            yield Static("", id="footerbar")

    def on_mount(self) -> None:
        db.init_db()
        self._apply_global_visibility()
        self._render_splash(force_banner=True)

        self.set_interval(0.06, self._tick_splash)  # splash animation
        self.set_interval(1.0, self._refresh)       # main refresh
        self._apply_responsive()


    # ---------------- Responsive layout ----------------
    def _apply_responsive(self) -> None:
        w, h = self.size.width, self.size.height

        # Breakpoints
        tiny  = (w < 92) or (h < 24)
        stack = (not tiny) and (w < 120)
        wide  = (not tiny) and (not stack)
        short = h < 32

        scr = self.screen
        for cls in ("wide", "stack", "tiny", "short"):
            scr.remove_class(cls)
        scr.add_class("tiny" if tiny else ("stack" if stack else "wide"))
        if short:
            scr.add_class("short")

        self._layout_profile = "tiny" if tiny else ("stack" if stack else "wide")

        # Preferenze utente (non perderle al resize)
        if not hasattr(self, "_user_view_mode"):
            self._user_view_mode = self.view_mode
        if not hasattr(self, "_user_show_details"):
            self._user_show_details = self.show_details
        if not hasattr(self, "_forced_minimal"):
            self._forced_minimal = False

        if self.ui_mode == "main":
            if tiny:
                self._forced_minimal = True
                self.view_mode = "minimal"
                self.show_details = False
            else:
                if self._forced_minimal:
                    self.view_mode = self._user_view_mode
                    self.show_details = self._user_show_details
                    self._forced_minimal = False

            self._apply_visibility()
            self._update_footerbar()

    def on_resize(self, event) -> None:
        self._apply_responsive()

    # -------- Key handling (robust Enter/Esc) --------
    def on_key(self, event: events.Key) -> None:
        k = (event.key or "").lower()

        if k in ("enter", "return"):
            if self.ui_mode == "splash":
                self.action_continue()
                event.stop()
                return
            self.action_open_selected()
            event.stop()
            return

        if k == "escape":
            self.action_close_report()
            event.stop()
            return

    # ---------------- Splash ----------------
    def action_continue(self) -> None:
        self.ui_mode = "main"
        self._apply_global_visibility()
        self._apply_responsive()
        self._refresh()
        self.query_one("#feed", ListView).focus()

    def _apply_global_visibility(self) -> None:
        splash = self.query_one("#splash", Container)
        app = self.query_one("#app", Container)

        if self.ui_mode == "splash":
            splash.remove_class("hidden")
            app.add_class("hidden")
            return

        splash.add_class("hidden")
        app.remove_class("hidden")
        self._apply_visibility()

    def _splash_banner_text(self) -> str:
        host = socket.gethostname()
        kernel = platform.release()
        up = _fmt_uptime(_read_uptime_seconds())
        ip = _get_lan_ip()

        line0 = "[bold green]ARGUS[/bold green]  [dim]— Argus watches. You decide.[/dim]"
        line1 = "[bold cyan]OPERATOR[/bold cyan]  [bold]Antonio Ruocco[/bold]"
        line2 = f"[dim]root@{host} | v{ARGUS_VERSION} | kernel {kernel} | uptime {up} | ip {ip}[/dim]"
        return "\n".join((line0, line1, line2))

    # ---------------- Digit-cascade (ARGUS made of 0/1 encoding "I watch U") ----------------
    def _dm_ensure(self) -> None:
        # keep one-screen compact
        w = max(56, min(self.size.width - 6, 120))
        h = 12

        if getattr(self, "_dm_w", None) == w and getattr(self, "_dm_h", None) == h:
            return

        self._dm_w = w
        self._dm_h = h
        self._dm_done = False

        logo = _logo_argus_lines()
        lh = len(logo)
        lw = len(logo[0]) if logo else 0

        x0 = max(0, (w - lw) // 2)
        y0 = max(0, (h - lh) // 2)

        targets: List[Tuple[int, int]] = []
        targets_by_col: Dict[int, List[int]] = {}

        for y in range(lh):
            for x in range(lw):
                if logo[y][x] != " ":
                    tx, ty = x0 + x, y0 + y
                    targets.append((tx, ty))
                    targets_by_col.setdefault(tx, []).append(ty)

        for x in targets_by_col:
            targets_by_col[x] = sorted(targets_by_col[x])  # top->bottom

        self._dm_targets = set(targets)
        self._dm_targets_by_col = targets_by_col

        self._dm_filled = {}   # (x,y) -> digit
        self._dm_falling = {}  # x -> (y, digit, target_y)

        # map each target cell to a bit (ASCII bits of "I watch U")
        msg = "I watch U"
        bits = "".join(f"{b:08b}" for b in msg.encode("ascii"))
        ordered = sorted(targets, key=lambda t: (t[1], t[0]))  # row-major
        self._dm_target_digit = {pos: bits[i % len(bits)] for i, pos in enumerate(ordered)}

    def _dm_step(self) -> None:
        self._dm_ensure()
        if self._dm_done:
            return

        # spawn per column if needed (one falling digit per column)
        for x, ys in self._dm_targets_by_col.items():
            if x in self._dm_falling:
                continue

            next_ty = None
            for ty in ys:
                if (x, ty) not in self._dm_filled:
                    next_ty = ty
                    break
            if next_ty is None:
                continue

            d = self._dm_target_digit.get((x, next_ty), "0")
            self._dm_falling[x] = (-1, d, next_ty)

        # advance + lock
        new_falling = {}
        for x, (y, d, ty) in self._dm_falling.items():
            y2 = y + 1
            if y2 >= ty:
                self._dm_filled[(x, ty)] = d
            else:
                new_falling[x] = (y2, d, ty)
        self._dm_falling = new_falling

        if self._dm_targets and len(self._dm_filled) >= len(self._dm_targets):
            self._dm_done = True

    def _dm_render(self) -> Text:
        self._dm_ensure()
        w, h = self._dm_w, self._dm_h

        grid = [[" " for _ in range(w)] for _ in range(h)]

        for (x, y), d in self._dm_filled.items():
            if 0 <= x < w and 0 <= y < h:
                grid[y][x] = d

        for x, (y, d, _ty) in self._dm_falling.items():
            if 0 <= x < w and 0 <= y < h and grid[y][x] == " ":
                grid[y][x] = d

        txt = Text("\n".join("".join(r) for r in grid), style="green")

        # bold target cells so ARGUS pops
        for (x, y) in self._dm_targets:
            idx = y * (w + 1) + x
            if 0 <= idx < len(txt):
                txt.stylize("bold green", idx, idx + 1)

        return txt

    def _splash_ready_line(self) -> str:
        total = len(getattr(self, "_dm_targets", [])) or 1
        filled = len(getattr(self, "_dm_filled", {})) or 0
        pct = int(min(100, (filled * 100) / total))
        done = bool(getattr(self, "_dm_done", False)) or pct >= 100

        width = 28
        fill_n = int((pct * width) / 100)
        bar_f = "█" * fill_n
        bar_e = "░" * (width - fill_n)

        if done:
            badge = "[bold black on #00ff00] READY [/bold black on #00ff00]"
            tail = "[#00ff00]press Enter[/#00ff00]"
        else:
            badge = "[dim]BOOT[/dim]"
            tail = "[dim]initializing...[/dim]"

        return (
            f"{badge} "
            f"[#00ff00]{bar_f}[/#00ff00][dim]{bar_e}[/dim]  "
            f"[#00ff00]{pct:3d}%[/#00ff00]  {tail}"
        )

    def _splash_body_render_text(self) -> str:
        txt = "\n".join(_splash_body_lines())
        txt += "\n\n" + self._splash_ready_line()
        return txt

    def _render_splash(self, force_banner: bool = False) -> None:
        banner = self.query_one("#splash_banner", Static)
        matrix = self.query_one("#splash_matrix", Static)
        body = self.query_one("#splash_body", Static)

        # banner: update at most twice per second (uptime changes)
        now = time.time()
        if force_banner or (now - self._last_banner_update_ts) >= 0.5:
            btxt = self._splash_banner_text()
            if btxt != self._last_banner_text:
                banner.update(btxt)
                self._last_banner_text = btxt
            self._last_banner_update_ts = now

        matrix.update(self._dm_render())
        body.update(self._splash_body_render_text())

    def _tick_splash(self) -> None:
        if self.ui_mode != "splash":
            return
        self._dm_step()
        self._render_splash()

    # ---------------- Main UI ----------------
    def action_toggle_view(self) -> None:
        if self.ui_mode != "main":
            return
        self.view_mode = "minimal" if self.view_mode == "dashboard" else "dashboard"
        self._user_view_mode = self.view_mode
        self._apply_visibility()

    def action_toggle_details(self) -> None:
        if self.ui_mode != "main":
            return
        self.show_details = not self.show_details
        self._user_show_details = self.show_details
        self._apply_visibility()

    def _apply_visibility(self) -> None:
        summary = self.query_one("#summary", Static)
        detail_box = self.query_one("#detail_box", VerticalScroll)

        if self.view_mode == "minimal":
            summary.add_class("hidden")
            detail_box.add_class("hidden")
            return

        summary.remove_class("hidden")
        prof = getattr(self, "_layout_profile", "wide")
        if self.show_details and (self.size.width >= 100 or prof == "stack"):
            detail_box.remove_class("hidden")
        else:
            detail_box.add_class("hidden")

    def action_close_report(self) -> None:
        if self._detail_override_text is None:
            return
        self._detail_override_text = None
        self._detail_override_event_id = None
        self._update_detail()

    def action_start_monitor(self) -> None:
        try:
            subprocess.run(["argus", "start"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Start requested from TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Start error ({e!r})", entity="tui")
        self._refresh()

    def action_stop_monitor(self) -> None:
        try:
            subprocess.run(["argus", "stop"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Stop requested from TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Stop error ({e!r})", entity="tui")
        self._refresh()

    def action_maintenance_30(self) -> None:
        try:
            subprocess.run(["argus", "maintenance", "30m"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Maintenance 30m enabled from TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Maintenance error ({e!r})", entity="tui")
        self._refresh()

    def action_mute_10(self) -> None:
        try:
            subprocess.run(["argus", "mute", "10m"], timeout=2)
            db.add_event(code="SYS", severity="INFO", message="Mute 10m enabled from TUI.", entity="tui")
        except Exception as e:
            db.add_event(code="SYS", severity="WARNING", message=f"Mute error ({e!r})", entity="tui")
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
            if hasattr(db, "clear_all_events"):
                db.clear_all_events()  # type: ignore[attr-defined]
            else:
                db.clear_events()
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
        if self.ui_mode != "main":
            return
        if not self._selected:
            return

        e = self._selected.event
        eid = int(e.get("id") or 0)
        md_path = (e.get("report_md_path") or "").strip()
        if not md_path:
            db.add_event(code="SYS", severity="INFO", message="No report associated to this event.", entity="tui")
            self._refresh()
            return

        p = Path(md_path)
        if not p.exists():
            db.add_event(code="SYS", severity="WARNING", message=f"Report not found: {md_path}", entity="tui")
            self._refresh()
            return

        try:
            txt = p.read_text(encoding="utf-8")
        except Exception as ex:
            txt = f"Report read error: {ex!r}\nPath: {md_path}"

        self._detail_override_text = txt
        self._detail_override_event_id = eid
        self.query_one("#detail_text", Static).update(txt)

    def action_trust_selected(self) -> None:
        if self.ui_mode != "main":
            return

        if not self._selected:
            db.add_event(code="SYS", severity="INFO", message="Trust: select an event first.", entity="tui")
            self._refresh()
            return

        e = self._selected.event
        code = (e.get("code") or "")
        msg = (e.get("message") or "")

        if code != "SEC-04":
            db.add_event(code="SYS", severity="INFO", message="Trust: valid only for SEC-04.", entity="tui")
            self._refresh()
            return

        m = RE_SEC04.search(msg)
        if not m:
            db.add_event(code="SYS", severity="WARNING", message="Trust: failed to parse proc/port/bind.", entity="tui")
            self._refresh()
            return

        proc = m.group("proc")
        port = int(m.group("port"))
        bind = m.group("bind").upper()

        _, out = add_sec04_trust(proc, port, bind)
        db.add_event(code="SYS", severity="INFO", message=f"Trust SEC-04: {out}", entity="tui")
        self._refresh()

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
        advice_txt = "\n".join([f"  • {a}" for a in advice]) if advice else "  • (actions coming soon)"
        has_report = "YES" if (e.get("report_md_path") or "").strip() else "NO"

        detail_text.update(
            "\n".join(
                [
                    f"{code} ({sev})",
                    f"{ts}",
                    "",
                    "What happened",
                    f"  {msg}",
                    "",
                    "Entity",
                    f"  {ent if ent else '(n/a)'}",
                    "",
                    "What to do now",
                    f"{advice_txt}",
                    "",
                    f"Report: {has_report}  (Enter opens, Esc goes back)",
                ]
            )
        )

    def _update_footerbar(self) -> None:
        if self.ui_mode != "main":
            return

        footer = self.query_one("#footerbar", Static)

        KEY_BG = "#30363d"
        KEY_FG = "#e6edf3"
        OK_BG = "#1f6feb"
        DANGER_BG = "#8b2f2f"
        DIM = "[dim]|[/dim]"

        def cap(key: str, bg: str = KEY_BG) -> str:
            return f"[bold {KEY_FG} on {bg}] {key} [/bold {KEY_FG} on {bg}]"

        run_line = _status_runstop()
        state = run_line.split(":", 1)[1].strip() if ":" in run_line else run_line.strip()
        state = state or "UNKNOWN"

        if "RUN" in state.upper():
            state_col = "#3fb950"
        elif "STOP" in state.upper():
            state_col = "#f85149"
        else:
            state_col = "#d29922"

        view = "Dashboard" if self.view_mode == "dashboard" else "Minimal"
        prof = getattr(self, "_layout_profile", "wide")
        det_on = (self.view_mode == "dashboard" and self.show_details and (self.size.width >= 100 or prof == "stack"))
        det = "ON" if det_on else "OFF"

        flags = []
        if _flag_badge("mute"):
            flags.append("[#d29922]MUTE[/#d29922]")
        if _flag_badge("maintenance"):
            flags.append("[#58a6ff]MAINT[/#58a6ff]")
        flags_txt = " ".join(flags) if flags else "[dim]none[/dim]"

        w = self.size.width

        if w >= 118:
            line1 = (
                f"{cap('S', OK_BG)}[dim] Start[/dim]  "
                f"{cap('X', DANGER_BG)}[dim] Stop[/dim]  "
                f"{cap('D')}[dim] Details[/dim]  "
                f"{cap('V')}[dim] View[/dim]  "
                f"{cap('T')}[dim] Trust[/dim]  "
                f"{cap('K')}[dim] Clear[/dim]  "
                f"{cap('M')}[dim] Maint[/dim]  "
                f"{cap('U')}[dim] Mute[/dim]  "
                f"{cap('Enter', OK_BG)}[dim] Report[/dim]  "
                f"{cap('Esc')}[dim] Back[/dim]  "
                f"{cap('Q', DANGER_BG)}[dim] Quit[/dim]"
            )
        elif w >= 92:
            line1 = (
                f"{cap('S', OK_BG)}[dim] Start[/dim]  "
                f"{cap('X', DANGER_BG)}[dim] Stop[/dim]  "
                f"{cap('V')}[dim] View[/dim]  "
                f"{cap('D')}[dim] Details[/dim]  "
                f"{cap('Enter', OK_BG)}[dim] Report[/dim]  "
                f"{cap('Q', DANGER_BG)}[dim] Quit[/dim]"
            )
        else:
            line1 = (
                f"{cap('S', OK_BG)}[dim] Start[/dim]  "
                f"{cap('X', DANGER_BG)}[dim] Stop[/dim]  "
                f"{cap('Enter', OK_BG)}[dim] Report[/dim]  "
                f"{cap('Q', DANGER_BG)}[dim] Quit[/dim]"
            )

        line2 = (
            f"[bold]STATE[/bold] [{state_col}]{state}[/{state_col}]  {DIM} "
            f"[bold]VIEW[/bold] {view}  {DIM} "
            f"[bold]DETAILS[/bold] {det}  {DIM} "
            f"[bold]FLAGS[/bold] {flags_txt}"
        )

        footer.update(line1 + "\\n" + line2)

    def _refresh(self) -> None:
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

        top_id = int(visible[0].get("id") or 0) if visible else 0
        feed_sig = (top_id, len(visible))

        last_10m = [e for e in visible if int(e.get("ts", 0)) >= since_10m]
        state = _global_state(last_10m)
        threat = _score(last_10m, "SEC-")
        health = _score(last_10m, "HEA-")

        temp = format_cpu_temp()
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
            out.append("Security (today)")
            any_sec = False
            for c in ["SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-05"]:
                if c in counts_today:
                    any_sec = True
                    out.append(f"  {CODE_ICON.get(c,'•')} {c}  x{counts_today[c]}")
            if not any_sec:
                out.append("  (no SEC events today)")

            out.append("")
            out.append("SEC-03 — Unusual sudo seen today (first-seen)")
            if not sec03_today:
                out.append("  (no new entries today)")
            else:
                for row in sec03_today:
                    t = datetime.fromtimestamp(int(row["first_ts"])).strftime("%H:%M:%S")
                    user, cmd = _parse_sec03_key(row.get("key", ""))
                    cnt = int(row.get("count", 1))
                    cmd_s = cmd if len(cmd) <= 70 else cmd[:67] + "..."
                    out.append(f"  {t}  🧨  {user}  {cmd_s}  (x{cnt})")

            out.append("")
            out.append("SEC-04 — New listening services seen today (first-seen)")
            if not sec04_today:
                out.append("  (no new entries today)")
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
