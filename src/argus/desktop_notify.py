from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from typing import Dict, Optional


def _has_session_bus() -> bool:
    # In un user-service systemd normalmente c'è.
    # Se manca, notify-send/gdbus potrebbero fallire: noi gestiamo senza crash.
    return bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("XDG_RUNTIME_DIR"))


class DesktopNotifier:
    """
    Desktop notifications via freedesktop (D-Bus).
    Primary backend: notify-send (libnotify) -> D-Bus
    Fallback: gdbus call -> org.freedesktop.Notifications
    Includes a small throttle to avoid spamming.
    """

    def __init__(self, min_interval_s: int = 60, timeout_ms: int = 8000) -> None:
        self.min_interval_s = int(min_interval_s)
        self.timeout_ms = int(timeout_ms)
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}

    def _throttled(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._last.get(key, 0.0)
            if (now - last) < self.min_interval_s:
                return True
            self._last[key] = now
        return False

    def notify(
        self,
        title: str,
        body: str,
        *,
        urgency: str = "critical",
        key: Optional[str] = None,
        timeout_ms: Optional[int] = None,
    ) -> bool:
        """
        Returns True if a backend was executed successfully, False otherwise.
        """
        title = (title or "").strip()[:180]
        body = (body or "").strip()[:800]
        if not title:
            title = "ARGUS"

        if key and self._throttled(key):
            return False

        tmo = self.timeout_ms if timeout_ms is None else int(timeout_ms)

        # Prefer notify-send (simplest, widespread)
        if shutil.which("notify-send"):
            return self._notify_send(title, body, urgency=urgency, timeout_ms=tmo)

        # Fallback: gdbus call
        if shutil.which("gdbus"):
            return self._gdbus_notify(title, body, timeout_ms=tmo)

        return False

    def _notify_send(self, title: str, body: str, *, urgency: str, timeout_ms: int) -> bool:
        try:
            # --app-name aiuta a raggruppare nei notification center
            cmd = [
                "notify-send",
                "--app-name", "ARGUS",
                "--urgency", urgency,
                "--expire-time", str(timeout_ms),
                title,
                body,
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
            return True
        except Exception:
            return False

    def _gdbus_notify(self, title: str, body: str, *, timeout_ms: int) -> bool:
        # org.freedesktop.Notifications.Notify(app_name, replaces_id, app_icon, summary, body, actions, hints, expire_timeout)
        try:
            if not _has_session_bus():
                return False
            cmd = [
                "gdbus", "call",
                "--session",
                "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications",
                "--method", "org.freedesktop.Notifications.Notify",
                "ARGUS", "0", "", title, body,
                "[]", "{}", str(timeout_ms),
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
            return True
        except Exception:
            return False


def build_critical_notification(code: str, entity: str, message: str) -> tuple[str, str, str]:
    code_u = (code or "").upper().strip()
    ent = (entity or "").strip()
    msg = (message or "").strip()

    title = f"ARGUS {code_u} — CRITICAL"
    if ent:
        body = f"{ent}\n{msg}" if msg else ent
    else:
        body = msg or "(no message)"
    key = f"{code_u}|{ent}" if ent else code_u
    return title, body, key
