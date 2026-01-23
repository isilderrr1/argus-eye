from __future__ import annotations

from argus import db
from argus.desktop_notify import DesktopNotifier, build_critical_notification


def run_notification_test() -> bool:
    """
    Creates a CRITICAL SYS event and attempts a desktop notification.
    Returns True if we attempted to send a notification successfully.
    """
    db.init_db()

    code = "SYS"
    sev = "CRITICAL"
    entity = "notify-test"
    message = "Desktop notification test (CRITICAL). If you see this popup, you're good."

    # Store event (so you also see it in TUI/events)
    db.add_event(code=code, severity=sev, message=message, entity=entity)

    # Send notification (same behavior as monitor side: throttle is not relevant here)
    notifier = DesktopNotifier(min_interval_s=0, timeout_ms=9000)
    title, body, key = build_critical_notification(code, entity, message)
    ok = notifier.notify(title, body, urgency="critical", key=key)

    return ok
