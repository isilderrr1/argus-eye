from __future__ import annotations

import json
import os
from typing import Dict, List, Tuple

from argus.collectors.disk import list_mount_usage, fmt_gb


class DiskUsageDetector:
    """
    HEA-03 — Disk almost full
    - WARNING: >= warn_pct for N consecutive checks
    - CRITICAL: >= crit_pct for N consecutive checks
    - Filters handled by collector (fstype + <1GB)
    """

    def __init__(
        self,
        warn_pct: int = 85,
        crit_pct: int = 95,
        consecutive: int = 2,
        min_total_gb: int = 1,
        clear_hysteresis_pct: int = 3,  # when usage drops below threshold - 3, allow retrigger
    ) -> None:
        # env overrides (useful for quick tests)
        self.warn_pct = int(os.getenv("ARGUS_DISK_WARN", str(warn_pct)))
        self.crit_pct = int(os.getenv("ARGUS_DISK_CRIT", str(crit_pct)))
        self.consecutive = int(os.getenv("ARGUS_DISK_CONSEC", str(consecutive)))

        self.min_total_bytes = int(min_total_gb) * (1 << 30)
        self.clear_hyst = int(clear_hysteresis_pct)

        self._warn_streak: Dict[str, int] = {}
        self._crit_streak: Dict[str, int] = {}
        self._active_level: Dict[str, str] = {}  # mount -> "WARNING"/"CRITICAL"

    def poll(self) -> List[Tuple[str, str, str, str]]:
        """
        Returns list of (severity, entity, message, details_json)
        """
        out: List[Tuple[str, str, str, str]] = []
        mounts = list_mount_usage(min_total_bytes=self.min_total_bytes)

        current_mounts = {m.mount for m in mounts}

        # cleanup removed mounts
        for m in list(self._warn_streak.keys()):
            if m not in current_mounts:
                self._warn_streak.pop(m, None)
                self._crit_streak.pop(m, None)
                self._active_level.pop(m, None)

        for m in mounts:
            mount = m.mount
            used = int(m.used_pct)

            above_warn = used >= self.warn_pct
            above_crit = used >= self.crit_pct

            self._warn_streak[mount] = (self._warn_streak.get(mount, 0) + 1) if above_warn else 0
            self._crit_streak[mount] = (self._crit_streak.get(mount, 0) + 1) if above_crit else 0

            # allow retrigger when it drops enough
            active = self._active_level.get(mount)
            if active == "CRITICAL" and used <= (self.crit_pct - self.clear_hyst):
                self._active_level.pop(mount, None)
                active = None
            if active == "WARNING" and used <= (self.warn_pct - self.clear_hyst):
                self._active_level.pop(mount, None)
                active = None

            details = json.dumps(
                {
                    "mount": mount,
                    "used_pct": used,
                    "total": fmt_gb(m.total_bytes),
                    "used": fmt_gb(m.used_bytes),
                    "fstype": m.fstype,
                    "thresholds": {"warn": self.warn_pct, "crit": self.crit_pct, "consecutive": self.consecutive},
                },
                ensure_ascii=False,
            )

            # priority: CRITICAL
            if self._crit_streak[mount] >= self.consecutive and active != "CRITICAL":
                msg = (
                    f"Disk almost full: {mount} at {used}% "
                    f"(≥{self.crit_pct}% for {self.consecutive} checks)."
                )
                out.append(("CRITICAL", mount, msg, details))
                self._active_level[mount] = "CRITICAL"
                continue

            # WARNING (only if not already critical)
            if self._warn_streak[mount] >= self.consecutive and active not in ("WARNING", "CRITICAL"):
                msg = (
                    f"Low disk space: {mount} at {used}% "
                    f"(≥{self.warn_pct}% for {self.consecutive} checks)."
                )
                out.append(("WARNING", mount, msg, details))
                self._active_level[mount] = "WARNING"

        return out
