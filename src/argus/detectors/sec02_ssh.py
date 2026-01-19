from __future__ import annotations

import re
import time
from collections import deque
from ipaddress import ip_address, ip_network
from typing import Deque, Dict, Optional, Tuple


# --- Regole v1 (come da tua specifica) ---
FAIL_WINDOW_SEC = 120         # 2 minuti (dopo X fallimenti)
SUCCESS_WINDOW_SEC = 60      # 1 minuto (successo dopo fallimento)
CRIT_THRESHOLD = 3            # 3 fallimenti

COOLDOWN_FAIL_SEC = 60       # 1 minuto cooldown dopo il successo (non sovrascrivere troppe volte)

LAN_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("100.64.0.0/10"),   # CGNAT
    ip_network("169.254.0.0/16"),  # link-local
    ip_network("fc00::/7"),        # IPv6 ULA
    ip_network("fe80::/10"),       # IPv6 link-local
]

# Regex principali (coprono molte varianti reali)
RE_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port",
    re.IGNORECASE,
)
RE_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port",
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
    return None


def parse_ssh_success(line: str) -> Optional[Tuple[str, str]]:
    m = RE_SUCCESS.search(line)
    if m:
        return m.group("ip"), m.group("user")
    return None


class SshSuccessAfterFailsDetector:
    """
    Rileva quando un SSH fallito è seguito da un login riuscito.
    Viene emesso un evento CRITICAL se succede.
    """
    def __init__(self) -> None:
        self.failures: Dict[str, Deque[int]] = {}
        self.successes: Dict[str, Deque[int]] = {}
        self.last_emitted: Dict[Tuple[str, str], int] = {}

    def _prune(self, q: Deque[int], window: int, now: int) -> None:
        while q and (now - q[0]) > window:
            q.popleft()

    def handle_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        """
        Se rileva una sequenza di eventi fallimento + successo, ritorna (severity, ip, message)
        """
        success = parse_ssh_success(line)
        if success:
            ip, user = success
            now = _now()

            # Salva il successo
            q_success = self.successes.setdefault(ip, deque())
            q_success.append(now)

            # Rimuovi successi più vecchi di 1 minuto
            self._prune(q_success, SUCCESS_WINDOW_SEC, now)

            # Se abbiamo almeno un successo, controlliamo se abbiamo fallimenti precedenti
            if len(q_success) >= 1 and ip in self.failures:
                q_fail = self.failures[ip]
                self._prune(q_fail, FAIL_WINDOW_SEC, now)

                # Se ci sono almeno 3 fallimenti entro 2 minuti e un successo successivo
                if len(q_fail) >= CRIT_THRESHOLD:
                    # Downgrade per LAN
                    is_lan = ip_is_lan(ip)
                    sev = downgrade_severity_for_lan("CRITICAL", is_lan)
                    msg = f"Successo dopo {len(q_fail)} tentativi falliti da {ip} (user={user})"
                    
                    # Imposta cooldown per evitare eventi continui
                    key = (ip, sev)
                    last = self.last_emitted.get(key, 0)
                    if now - last < COOLDOWN_FAIL_SEC:
                        return None
                    self.last_emitted[key] = now

                    return sev, ip, msg

        failure = parse_ssh_failure(line)
        if failure:
            ip, user = failure
            now = _now()

            # Aggiungi il fallimento
            q_fail = self.failures.setdefault(ip, deque())
            q_fail.append(now)

            # Rimuovi fallimenti più vecchi di 2 minuti
            self._prune(q_fail, FAIL_WINDOW_SEC, now)

        return None
