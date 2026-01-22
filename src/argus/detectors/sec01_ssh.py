from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


_FAIL_PATTERNS = [
    # Debian/Ubuntu sshd
    re.compile(r"Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    # PAM-style (sometimes appears)
    re.compile(r"authentication failure;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)", re.IGNORECASE),
]


def _ip_scope(ip: str) -> str:
    ip = (ip or "").strip()
    if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
        return "LOCAL"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "LAN"
    if ip.startswith("172."):
        # 172.16.0.0/12
        try:
            second = int(ip.split(".", 2)[1])
            if 16 <= second <= 31:
                return "LAN"
        except Exception:
            pass
    if ip.startswith("169.254."):
        return "LAN"
    return "GLOBAL"


def _downgrade_by_scope(sev: str, scope: str) -> str:
    sev = (sev or "").upper()
    scope = (scope or "").upper()

    # Localhost = informational only
    if scope == "LOCAL":
        return "INFO"

    # LAN may be less serious than GLOBAL
    if scope == "LAN" and sev == "CRITICAL":
        return "WARNING"

    return sev


@dataclass
class _Bucket:
    ts: List[int]
    last_info_emit: int = 0
    last_alert_emit: int = 0


class SshBruteForceDetector:
    """
    SEC-01: Detect repeated SSH authentication failures.

    - Tracks failures per source IP in a sliding window
    - Emits:
        * INFO (rate-limited) for first-seen/occasional failures
        * WARNING / CRITICAL when thresholds are reached
    """

    def __init__(
        self,
        window_s: int = 60,
        warn_attempts: int = 5,
        crit_attempts: int = 12,
        info_cooldown_s: int = 120,
        alert_cooldown_s: int = 60,
    ) -> None:
        self.window_s = int(window_s)
        self.warn_attempts = int(warn_attempts)
        self.crit_attempts = int(crit_attempts)
        self.info_cooldown_s = int(info_cooldown_s)
        self.alert_cooldown_s = int(alert_cooldown_s)

        self._by_ip: Dict[str, _Bucket] = {}

    def _prune(self, now: int, b: _Bucket) -> None:
        cutoff = now - self.window_s
        # keep only timestamps >= cutoff
        b.ts = [t for t in b.ts if t >= cutoff]

    def _parse_fail(self, line: str) -> Optional[Tuple[str, str]]:
        for rx in _FAIL_PATTERNS:
            m = rx.search(line or "")
            if m:
                user = (m.groupdict().get("user") or "").strip() or "unknown"
                ip = (m.groupdict().get("ip") or "").strip()
                if ip:
                    return ip, user
        return None

    def handle_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        parsed = self._parse_fail(line)
        if not parsed:
            return None

        ip, user = parsed
        now = int(time.time())

        b = self._by_ip.get(ip)
        if b is None:
            b = _Bucket(ts=[])
            self._by_ip[ip] = b

        b.ts.append(now)
        self._prune(now, b)
        count = len(b.ts)

        scope = _ip_scope(ip)

        # ALERT path
        if count >= self.crit_attempts:
            sev = _downgrade_by_scope("CRITICAL", scope)
            if (now - b.last_alert_emit) >= self.alert_cooldown_s:
                b.last_alert_emit = now
                msg = (
                    f"SSH brute-force suspected: {count} failed attempts in the last {self.window_s}s "
                    f"from {ip} [{scope}]."
                )
                return sev, ip, msg
            return None

        if count >= self.warn_attempts:
            sev = _downgrade_by_scope("WARNING", scope)
            if (now - b.last_alert_emit) >= self.alert_cooldown_s:
                b.last_alert_emit = now
                msg = (
                    f"SSH brute-force suspected: {count} failed attempts in the last {self.window_s}s "
                    f"from {ip} [{scope}]."
                )
                return sev, ip, msg
            return None

        # INFO path (rate-limited, to avoid noise)
        if (now - b.last_info_emit) >= self.info_cooldown_s:
            b.last_info_emit = now
            msg = f"SSH authentication failed from {ip} (user={user}) [{scope}]."
            return "INFO", ip, msg

        return None
