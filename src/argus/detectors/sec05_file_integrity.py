from __future__ import annotations

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass
from glob import glob
from typing import Dict, List, Optional, Tuple

from argus import db


# --- SPEC: paths ---
CRITICAL_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
]
CRITICAL_GLOBS = [
    "/etc/sudoers.d/*",
]

WARNING_PATHS = [
    "/etc/ssh/sshd_config",
    os.path.expanduser("~/.ssh/authorized_keys"),
    "/etc/crontab",
]

# per test sicuro: ARGUS_SEC05_TEST=~/argus_test.txt
TEST_EXTRA = os.environ.get("ARGUS_SEC05_TEST")
if TEST_EXTRA:
    WARNING_PATHS.append(os.path.expanduser(TEST_EXTRA))

# (opzionale) crontab utente (spesso non leggibile senza privilegi)
USER_CRON = f"/var/spool/cron/crontabs/{os.environ.get('USER','')}"
if USER_CRON and os.path.isfile(USER_CRON):
    WARNING_PATHS.append(USER_CRON)


def _now() -> int:
    return int(time.time())


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 64), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None
    except Exception:
        return None


def _stat_fingerprint(path: str) -> Optional[str]:
    """
    Fallback quando non possiamo leggere il contenuto (es. /etc/shadow senza permessi).
    Non è sha256, ma evita "silenzio totale" in ambienti home senza root.
    """
    try:
        st = os.stat(path)
        return f"mtime_ns={st.st_mtime_ns};size={st.st_size};mode={st.st_mode};uid={st.st_uid};gid={st.st_gid}"
    except FileNotFoundError:
        return None
    except Exception:
        return None


def file_fingerprint(path: str) -> Optional[str]:
    sha = _sha256_file(path)
    if sha is not None:
        return "SHA256:" + sha
    statfp = _stat_fingerprint(path)
    if statfp is not None:
        return "STAT:" + statfp
    return None


def is_pkg_manager_active() -> bool:
    """
    SPEC: auto-silenzio update se package manager attivo.
    Importante: NON includere snapd sempre-on, altrimenti tagga UPDATE continuamente.
    """
    procs = [
        "apt", "apt-get", "dpkg", "unattended-upgrades", "apt.systemd.daily",
    ]
    for p in procs:
        try:
            r = subprocess.run(
                ["pgrep", "-x", p],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def maintenance_active() -> bool:
    return db.get_flag("maintenance") is not None


def recent_sec02_or_sec03(within_s: int = 600) -> bool:
    """
    SPEC escalation: se entro 10 min ci sono SEC-02 o SEC-03 => CRITICAL.
    Per v1: guardiamo gli ultimi 50 eventi.
    """
    now = _now()
    for e in db.list_events(limit=50):
        try:
            ts = int(e["ts"])
        except Exception:
            continue
        if now - ts > within_s:
            continue
        if e.get("code") in ("SEC-02", "SEC-03"):
            sev = (e.get("severity") or "").upper()
            if sev in ("WARNING", "CRITICAL"):
                return True
    return False


@dataclass
class _FileState:
    current: Optional[str] = None
    pending: Optional[str] = None
    pending_count: int = 0
    last_emit_ts: int = 0


class FileIntegrityDetector:
    """
    SEC-05 — Modifica file critici
    - fingerprint: sha256 (fallback STAT)
    - debounce: 2 check consecutivi
    - maintenance: WARNING -> INFO
    - update active: WARNING -> INFO
    - escalation: se SEC-02 o SEC-03 recenti -> CRITICAL
    - cooldown: 30 min per file
    """

    DEBOUNCE_CHECKS = 2
    COOLDOWN_S = 30 * 60

    def __init__(self) -> None:
        self.state: Dict[str, _FileState] = {}

    def _expand_paths(self) -> Tuple[List[str], List[str]]:
        crit = list(CRITICAL_PATHS)
        for g in CRITICAL_GLOBS:
            crit.extend([p for p in glob(g) if os.path.isfile(p)])
        warn = [p for p in WARNING_PATHS if os.path.isfile(p)]

        def uniq(xs):
            seen = set()
            out = []
            for x in xs:
                if x not in seen:
                    out.append(x)
                    seen.add(x)
            return out

        return uniq(crit), uniq(warn)

    def _base_severity(self, path: str, crit_list: List[str], warn_list: List[str]) -> str:
        if path in crit_list or path.startswith("/etc/sudoers.d/"):
            return "CRITICAL"
        if path in warn_list:
            return "WARNING"
        return "INFO"

    def poll(self) -> List[Tuple[str, str, str]]:
        crit_list, warn_list = self._expand_paths()
        watch = crit_list + warn_list

        events: List[Tuple[str, str, str]] = []
        now = _now()

        pkg_active = is_pkg_manager_active()
        maint = maintenance_active()
        escal = recent_sec02_or_sec03(within_s=600)

        for path in watch:
            fp = file_fingerprint(path)

            # baseline: prima volta = memorizza e basta
            if path not in self.state:
                self.state[path] = _FileState(current=fp)
                continue

            st = self.state[path]
            if fp is None or st.current is None:
                st.current = fp
                st.pending = None
                st.pending_count = 0
                continue

            if fp == st.current:
                st.pending = None
                st.pending_count = 0
                continue

            # debounce: serve vedere la stessa "nuova impronta" 2 volte consecutive
            if st.pending == fp:
                st.pending_count += 1
            else:
                st.pending = fp
                st.pending_count = 1

            if st.pending_count < self.DEBOUNCE_CHECKS:
                continue

            # cooldown per file
            if now - st.last_emit_ts < self.COOLDOWN_S:
                st.current = fp
                st.pending = None
                st.pending_count = 0
                continue

            base = self._base_severity(path, crit_list, warn_list)
            sev = base
            tags: List[str] = []

            # maintenance/update: WARNING -> INFO
            if base == "WARNING" and maint:
                sev = "INFO"
                tags.append("MAINT")
            if base == "WARNING" and pkg_active:
                sev = "INFO"
                tags.append("UPDATE")

            # escalation: WARNING + SEC-02/03 recenti => CRITICAL (override)
            if base == "WARNING" and escal:
                sev = "CRITICAL"
                tags.append("ESCALATED")

            # microcopy SPEC
            if sev == "INFO" and (("MAINT" in tags) or ("UPDATE" in tags)):
                msg = f"File modificato durante manutenzione/aggiornamento: {path}."
            elif sev == "WARNING":
                msg = f"File importante modificato: {path}."
            else:  # CRITICAL
                msg = f"File critico modificato: {path}."

            # evidenza minima (senza hash lunghissimi nel testo principale)
            old_short = st.current[:18] + "..." if st.current else "n/a"
            new_short = fp[:18] + "..." if fp else "n/a"
            if tags:
                msg += " [" + ",".join(tags) + "]"
            msg += f" (old={old_short} new={new_short})"

            events.append((sev, path, msg))

            # commit stato
            st.current = fp
            st.pending = None
            st.pending_count = 0
            st.last_emit_ts = now

        return events
