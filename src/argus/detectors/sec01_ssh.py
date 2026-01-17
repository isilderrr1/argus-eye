from __future__ import annotations

import re
import time
from collections import deque
from ipaddress import ip_address, ip_network
from typing import Deque, Dict, Optional, Tuple


# --- Regole v1 (come da specifica) ---
WARN_WINDOW_SEC = 60          # 1 minuto
CRIT_WINDOW_SEC = 120         # 2 minuti
CRIT_THRESHOLD = 3            # 3 fallimenti in 2 minuti
WARN_THRESHOLD = 1            # 1 fallimento in 1 minuto

COOLDOWN_WARN_SEC = 60
COOLDOWN_CRIT_SEC = 120


LAN_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("100.64.0.0/10"),   # CGNAT
    ip_network("169.254.0.0/16"),  # link-local
    ip_network("fc00::/7"),        # IPv6 ULA
    ip_network("fe80::/10"),       # IPv6 link-local
]


# ✅ NOTA: qui usiamo \S (non \\S) perché è una regex, e la stringa è raw (r"...")
RE_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port",
    re.IGNORECASE,
)
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port",
    re.IGNORECASE,
)
# PAM line può non contenere user=..., quindi lo rendiamo opzionale
RE_PAM_FAIL = re.compile(
    r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?",
    re.IGNORECASE,
)


def _now() -> int:
    return int(time.time())


def ip_is_lan(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return False

    if ip.is_loopback:
        return True

    for net in LAN_NETS:
        if ip in net:
            return True

    if getattr(ip, "is_private", False):
        return True

    return False


def downgrade_severity_for_lan(sev: str, is_lan: bool) -> str:
    sev = sev.upper()
    if not is_lan:
        return sev
    if sev == "CRITICAL":
        return "WARNING"
    if sev == "WARNING":
        return "INFO"
    return "INFO"


def parse_ssh_failure(line: str) -> Optional[Tuple[str, str]]:
    m = RE_FAILED.search(line)
    if m:
        return m.group("ip"), m.group("user")

    m = RE_INVALID.search(line)
    if m:
        return m.group("ip"), m.group("user")

    m = RE_PAM_FAIL.search(line)
    if m:
        ip = m.group("ip")
        user = m.group("user") or "unknown"
        return ip, user

    return None


class SshBruteForceDetector:
    def __init__(self) -> None:
        self.failures: Dict[str, Deque[int]] = {}
        self.last_emitted: Dict[Tuple[str, str], int] = {}

    def _prune(self, q: Deque[int], window: int, now: int) -> None:
        while q and (now - q[0]) > window:
            q.popleft()

    def handle_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        parsed = parse_ssh_failure(line)
        if not parsed:
            return None

        ip, user = parsed
        now = _now()

        q = self.failures.setdefault(ip, deque())
        q.append(now)
        self._prune(q, CRIT_WINDOW_SEC, now)

        count_2m = len(q)
        count_1m = sum(1 for t in q if (now - t) <= WARN_WINDOW_SEC)

        raw_sev: Optional[str] = None
        if count_2m >= CRIT_THRESHOLD:
            raw_sev = "CRITICAL"
        elif count_1m >= WARN_THRESHOLD:
            raw_sev = "WARNING"

        if raw_sev is None:
            return None

        is_lan = ip_is_lan(ip)
        sev = downgrade_severity_for_lan(raw_sev, is_lan)

        cooldown = COOLDOWN_CRIT_SEC if raw_sev == "CRITICAL" else COOLDOWN_WARN_SEC
        key = (ip, raw_sev)
        last = self.last_emitted.get(key, 0)
        if now - last < cooldown:
            return None
        self.last_emitted[key] = now

        if raw_sev == "CRITICAL":
            msg = f"SSH brute-force sospetto da {ip}: {count_2m} fallimenti in 2 minuti (user={user})"
        else:
            msg = f"Tentativo SSH fallito da {ip}: {count_1m} fallimento in 1 minuto (user={user})"

        if is_lan:
            msg += " [LAN downgrade]"

        return sev, ip, msg
