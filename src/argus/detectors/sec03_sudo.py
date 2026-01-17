from __future__ import annotations

import re
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple


def _now() -> int:
    return int(time.time())


# sudo command line tipica in auth.log:
# sudo: antonio : TTY=pts/0 ; PWD=/home/antonio ; USER=root ; COMMAND=/usr/bin/apt update
RE_SUDO_CMD = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s+TTY=(?P<tty>[^;]+)\s*;\s+PWD=(?P<pwd>[^;]+)\s*;\s+USER=(?P<runas>[^;]+)\s*;\s+COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)

# sudo auth failure (varia, quindi match “grezzo” + optional info)
RE_SUDO_AUTH_FAIL = re.compile(
    r"sudo: pam_unix\(sudo:auth\): authentication failure",
    re.IGNORECASE,
)

# Pattern “alto rischio”
CRIT_PATTERNS = [
    re.compile(r"/etc/sudoers(\b|\.d/)", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|group|gshadow)\b", re.IGNORECASE),
    re.compile(r"\b(useradd|adduser|usermod)\b", re.IGNORECASE),
    re.compile(r"\bpasswd\b", re.IGNORECASE),
    re.compile(r"\bvisudo\b", re.IGNORECASE),
    re.compile(r"/etc/ssh/sshd_config\b", re.IGNORECASE),
    re.compile(r"authorized_keys\b", re.IGNORECASE),
    re.compile(r"\bufw\s+disable\b", re.IGNORECASE),
    re.compile(r"\biptables\b.*\s-F\b", re.IGNORECASE),
    re.compile(r"\bjournalctl\b.*--vacuum", re.IGNORECASE),
    re.compile(r"\btruncate\b.*(/var/log|auth\.log|syslog)", re.IGNORECASE),
    re.compile(r"\brm\b.*(/var/log|auth\.log|syslog)", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|\s*(sh|bash)", re.IGNORECASE),
    re.compile(r"\bwget\b.*\|\s*(sh|bash)", re.IGNORECASE),
]

# Pattern “medio rischio”
WARN_PATTERNS = [
    re.compile(r"\b(bash|sh|zsh)\b", re.IGNORECASE),
    re.compile(r"\bsu\b", re.IGNORECASE),
    re.compile(r"\bdpkg\b", re.IGNORECASE),
    re.compile(r"\bsystemctl\s+(stop|disable)\b", re.IGNORECASE),
    re.compile(r"\bchmod\b.*\s/(etc|usr|var)\b", re.IGNORECASE),
    re.compile(r"\bchown\b.*\s/(etc|usr|var)\b", re.IGNORECASE),
]


def classify_sudo_command(cmd: str) -> str:
    """Ritorna severità grezza: INFO / WARNING / CRITICAL."""
    for p in CRIT_PATTERNS:
        if p.search(cmd):
            return "CRITICAL"
    for p in WARN_PATTERNS:
        if p.search(cmd):
            return "WARNING"
    return "INFO"


class SudoActivityDetector:
    """
    SEC-03: Sudo / Privilege activity.

    - Logga comandi sudo, classificando rischio
    - Rileva molte auth failure sudo in breve tempo
    """

    # soglie per sudo auth failure
    FAIL_WARN_WINDOW = 60
    FAIL_CRIT_WINDOW = 120
    FAIL_WARN_TH = 2
    FAIL_CRIT_TH = 4

    # cooldown per non spammare eventi simili
    COOLDOWN_INFO = 30
    COOLDOWN_WARN = 60
    COOLDOWN_CRIT = 120

    def __init__(self) -> None:
        self.last_emitted: Dict[Tuple[str, str], int] = {}
        self.sudo_fail_ts: Deque[int] = deque()

    def _cooldown_for(self, sev: str) -> int:
        sev = sev.upper()
        if sev == "CRITICAL":
            return self.COOLDOWN_CRIT
        if sev == "WARNING":
            return self.COOLDOWN_WARN
        return self.COOLDOWN_INFO

    def _emit_ok(self, fingerprint: str, sev: str, now: int) -> bool:
        key = (fingerprint, sev.upper())
        last = self.last_emitted.get(key, 0)
        if now - last < self._cooldown_for(sev):
            return False
        self.last_emitted[key] = now
        return True

    def _prune_deque(self, q: Deque[int], window: int, now: int) -> None:
        while q and (now - q[0]) > window:
            q.popleft()

    def handle_line(self, line: str) -> Optional[Tuple[str, str, str]]:
        """
        Ritorna (severity, entity, message) oppure None.
        entity: utente locale
        """
        now = _now()

        # 1) sudo auth failures (password errata ripetuta)
        if RE_SUDO_AUTH_FAIL.search(line):
            self.sudo_fail_ts.append(now)
            self._prune_deque(self.sudo_fail_ts, self.FAIL_CRIT_WINDOW, now)

            count_2m = len(self.sudo_fail_ts)
            count_1m = sum(1 for t in self.sudo_fail_ts if (now - t) <= self.FAIL_WARN_WINDOW)

            sev = None
            if count_2m >= self.FAIL_CRIT_TH:
                sev = "CRITICAL"
            elif count_1m >= self.FAIL_WARN_TH:
                sev = "WARNING"

            if sev:
                fp = "sudo_auth_fail"
                if self._emit_ok(fp, sev, now):
                    msg = f"Sudo auth failure ripetuti: {count_1m} in 1m, {count_2m} in 2m (possibile password guessing locale)"
                    return sev, "local", msg
            return None

        # 2) sudo command execution
        m = RE_SUDO_CMD.search(line)
        if not m:
            return None

        user = m.group("user")
        runas = m.group("runas").strip()
        tty = m.group("tty").strip()
        pwd = m.group("pwd").strip()
        cmd = m.group("cmd").strip()

        raw_sev = classify_sudo_command(cmd)

        # fingerprint: utente + comando “normalizzato”
        cmd_norm = re.sub(r"\s+", " ", cmd)[:200]
        fp = f"{user}|{runas}|{cmd_norm}"

        if not self._emit_ok(fp, raw_sev, now):
            return None

        # messaggio user-friendly
        short_cmd = cmd_norm
        if len(short_cmd) > 120:
            short_cmd = short_cmd[:117] + "..."

        msg = f"Sudo command: {short_cmd} (runas={runas}, pwd={pwd}, tty={tty})"
        return raw_sev, user, msg
