from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


_FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"authentication failure;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)", re.IGNORECASE),
]

_SUCCESS_PATTERNS = [
    re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Accepted keyboard-interactive/pam for (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
]


def _ip_scope(ip: str) -> str:
    ip = (ip or "").strip()
    if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
        return "LOCAL"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "LAN"
    if ip.startswith("172."):
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
    if scope == "LOCAL":
        return "INFO"
    if scope == "LAN" and sev == "CRITICAL":
        return "WARNING"
    return sev


@dataclass
class _Bucket:
    fail_ts: List[int]
    last_emit: int = 0


class SshSuccessAfterFailsDetector:
    """
    SEC-02: Successful SSH login after previous failures from the same IP.

    - Tracks failures per IP
    - On success, if failures occurred within the last window -> emit event
    """

    def __init__(
        self,
        window_s: int = 600,     # 10 minutes
        min_fails: int = 3,
        cooldown_s: int = 60,
    ) -> None:
        self.window_s = int(window_s)
        self.min_fails = int(min_fails)
        self.cooldown_s = int(cooldown_s)
        self._by_ip: Dict[str, _Bucket] = {}

    def _prune(self, now: int, b: _Bucket) -> None:
        cutoff = now - self.window_s
        b.fail_ts = [t for t in b.fail_ts if t >= cutoff]

    def _parse_fail(self, line: str) -> Optional[Tuple[str, str]]:
        for rx in _FAIL_PATTERNS:
            m = rx.search(line or "")
            if m:
                user = (m.groupdict().get("user") or "").strip() or "unknown"
                ip = (m.groupdict().get("ip") or "").strip()
                if ip:
                    return ip, user
        return None

    def _parse_success(self, line: str) -> Optional[Tuple[str, str]]:
        for rx in _SUCCESS_PATTERNS:
            m = rx.search(line or "")
            if m:
                user = (m.groupdict().get("user") or "").strip() or "unknown"
                ip = (m.groupdict().get("ip") or "").strip()
                if ip:
                    return ip, user
        return None

    def handle_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        now = int(time.time())

        # record failures
        f = self._parse_fail(line)
        if f:
            ip, _user = f
            b = self._by_ip.get(ip)
            if b is None:
                b = _Bucket(fail_ts=[])
                self._by_ip[ip] = b
            b.fail_ts.append(now)
            self._prune(now, b)
            return None

        # check successes
        s = self._parse_success(line)
        if not s:
            return None

        ip, user = s
        b = self._by_ip.get(ip)
        if b is None:
            return None

        self._prune(now, b)
        fails = len(b.fail_ts)
        if fails < self.min_fails:
            return None

        # rate-limit
        if (now - b.last_emit) < self.cooldown_s:
            return None

        b.last_emit = now
        scope = _ip_scope(ip)

        # Severity model: WARNING by default, can be higher if lots of failures and global
        sev = "WARNING"
        if scope == "GLOBAL" and fails >= max(self.min_fails, 8):
            sev = "CRITICAL"
        sev = _downgrade_by_scope(sev, scope)

        msg = f"Successful SSH login after {fails} failed attempts from {ip} (user={user}) [{scope}]."
        return sev, ip, msg
