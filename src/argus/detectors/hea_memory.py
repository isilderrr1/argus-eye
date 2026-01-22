from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.memory import top_rss_processes


def _kb_to_mb(kb: int) -> int:
    return int(kb // 1024)


class MemoryPressureDetector:
    """
    HEA-05: Memory Pressure (Linux)

    Signals:
      - MemAvailable % (from /proc/meminfo)
      - SwapUsed % (SwapTotal - SwapFree)
      - swapin/swapout rate (pages/s) via /proc/vmstat pswpin/pswpout counters

    Emits:
      (sev, entity, msg, details_json)
    """

    def __init__(
        self,
        warn_mem_avail_pct: float = 10.0,
        crit_mem_avail_pct: float = 5.0,
        warn_swap_used_pct: float = 70.0,
        crit_swap_used_pct: float = 90.0,
        warn_swapout_ps: float = 200.0,
        crit_swapout_ps: float = 1000.0,
        consecutive: int = 2,
        clear_consecutive: int = 3,
        min_emit_interval_s: int = 15,
    ) -> None:
        self.warn_mem_avail_pct = float(warn_mem_avail_pct)
        self.crit_mem_avail_pct = float(crit_mem_avail_pct)
        self.warn_swap_used_pct = float(warn_swap_used_pct)
        self.crit_swap_used_pct = float(crit_swap_used_pct)
        self.warn_swapout_ps = float(warn_swapout_ps)
        self.crit_swapout_ps = float(crit_swapout_ps)

        self.consecutive = int(max(1, consecutive))
        self.clear_consecutive = int(max(1, clear_consecutive))
        self.min_emit_interval_s = int(max(0, min_emit_interval_s))

        self._prev: Optional[Dict[str, Any]] = None
        self._cur_level: str = "OK"  # OK | WARNING | CRITICAL

        self._hit_warn = 0
        self._hit_crit = 0
        self._hit_ok = 0

        self._last_emit_ts: float = 0.0

    def _rates(self, snap: Dict[str, Any]) -> Tuple[float, float]:
        """
        Return (swapin_ps, swapout_ps) from prev snapshot.
        """
        if not self._prev:
            return (0.0, 0.0)

        t1 = float(self._prev.get("ts") or 0.0)
        t2 = float(snap.get("ts") or 0.0)
        dt = max(0.001, t2 - t1)

        in1 = int(self._prev.get("pswpin") or 0)
        out1 = int(self._prev.get("pswpout") or 0)
        in2 = int(snap.get("pswpin") or 0)
        out2 = int(snap.get("pswpout") or 0)

        # counters are pages since boot
        din = max(0, in2 - in1)
        dout = max(0, out2 - out1)

        return (din / dt, dout / dt)

    def _metrics(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        mem_total_kb = int(snap.get("mem_total_kb") or 0)
        mem_avail_kb = int(snap.get("mem_available_kb") or 0)

        swap_total_kb = int(snap.get("swap_total_kb") or 0)
        swap_free_kb = int(snap.get("swap_free_kb") or 0)
        swap_used_kb = max(0, swap_total_kb - swap_free_kb)

        mem_avail_pct = (mem_avail_kb * 100.0 / mem_total_kb) if mem_total_kb > 0 else 0.0
        swap_used_pct = (swap_used_kb * 100.0 / swap_total_kb) if swap_total_kb > 0 else 0.0

        swapin_ps, swapout_ps = self._rates(snap)

        return {
            "mem_total_kb": mem_total_kb,
            "mem_available_kb": mem_avail_kb,
            "mem_available_pct": mem_avail_pct,
            "swap_total_kb": swap_total_kb,
            "swap_used_kb": swap_used_kb,
            "swap_used_pct": swap_used_pct,
            "swapin_ps": swapin_ps,
            "swapout_ps": swapout_ps,
        }

    def _decide_level(self, m: Dict[str, Any]) -> str:
        mem_av = float(m["mem_available_pct"])
        swap_used = float(m["swap_used_pct"])
        swapout_ps = float(m["swapout_ps"])

        crit = (
            mem_av <= self.crit_mem_avail_pct
            or swap_used >= self.crit_swap_used_pct
            or swapout_ps >= self.crit_swapout_ps
        )
        if crit:
            return "CRITICAL"

        warn = (
            mem_av <= self.warn_mem_avail_pct
            or swap_used >= self.warn_swap_used_pct
            or swapout_ps >= self.warn_swapout_ps
        )
        if warn:
            return "WARNING"

        return "OK"

    def _can_emit(self) -> bool:
        if self.min_emit_interval_s <= 0:
            return True
        return (time.time() - self._last_emit_ts) >= self.min_emit_interval_s

    def poll(self, snap: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
        """
        Return list of events:
          (severity, entity, message, details_json)
        """
        out: List[Tuple[str, str, str, str]] = []

        # baseline
        if self._prev is None:
            self._prev = snap
            return out

        m = self._metrics(snap)
        level = self._decide_level(m)

        # consecutive logic
        if level == "CRITICAL":
            self._hit_crit += 1
            self._hit_warn = 0
            self._hit_ok = 0
        elif level == "WARNING":
            self._hit_warn += 1
            self._hit_crit = 0
            self._hit_ok = 0
        else:
            self._hit_ok += 1
            self._hit_warn = 0
            self._hit_crit = 0

        # emit transitions (rate-limited)
        entity = "memory"
        details: Dict[str, Any] = {
            "mem_total_kb": int(m["mem_total_kb"]),
            "mem_available_kb": int(m["mem_available_kb"]),
            "mem_available_pct": float(m["mem_available_pct"]),
            "swap_total_kb": int(m["swap_total_kb"]),
            "swap_used_kb": int(m["swap_used_kb"]),
            "swap_used_pct": float(m["swap_used_pct"]),
            "swapin_ps": float(m["swapin_ps"]),
            "swapout_ps": float(m["swapout_ps"]),
            "thresholds": {
                "warn_mem_avail_pct": self.warn_mem_avail_pct,
                "crit_mem_avail_pct": self.crit_mem_avail_pct,
                "warn_swap_used_pct": self.warn_swap_used_pct,
                "crit_swap_used_pct": self.crit_swap_used_pct,
                "warn_swapout_ps": self.warn_swapout_ps,
                "crit_swapout_ps": self.crit_swapout_ps,
            },
        }

        def build_msg(sev: str) -> str:
            mem_av_pct = float(m["mem_available_pct"])
            mem_av_mb = _kb_to_mb(int(m["mem_available_kb"]))
            mem_total_mb = _kb_to_mb(int(m["mem_total_kb"]))

            swap_used_mb = _kb_to_mb(int(m["swap_used_kb"]))
            swap_total_mb = _kb_to_mb(int(m["swap_total_kb"]))

            swapout = float(m["swapout_ps"])
            swapin = float(m["swapin_ps"])

            return (
                f"Memory pressure {sev}: "
                f"MemAvailable {mem_av_pct:.2f}% ({mem_av_mb}MB/{mem_total_mb}MB), "
                f"SwapUsed {swap_used_mb}MB/{swap_total_mb}MB, "
                f"swapout {swapout:.2f} pages/s (swapin {swapin:.2f} pages/s)."
            )

        # WARNING/CRITICAL emit (only when entering or escalating)
        if level == "CRITICAL" and self._hit_crit >= self.consecutive:
            if self._cur_level != "CRITICAL" and self._can_emit():
                details["top_processes"] = top_rss_processes(limit=3)
                msg = build_msg("CRITICAL")
                out.append(("CRITICAL", entity, msg, json.dumps(details, ensure_ascii=False)))
                self._cur_level = "CRITICAL"
                self._last_emit_ts = time.time()

        elif level == "WARNING" and self._hit_warn >= self.consecutive:
            if self._cur_level == "OK" and self._can_emit():
                details["top_processes"] = top_rss_processes(limit=3)
                msg = build_msg("WARNING")
                out.append(("WARNING", entity, msg, json.dumps(details, ensure_ascii=False)))
                self._cur_level = "WARNING"
                self._last_emit_ts = time.time()

        # Clear emit (INFO) when returning to OK
        elif level == "OK" and self._hit_ok >= self.clear_consecutive:
            if self._cur_level in ("WARNING", "CRITICAL") and self._can_emit():
                msg = "Memory pressure cleared: MemAvailable and swap activity returned to normal."
                out.append(("INFO", entity, msg, json.dumps(details, ensure_ascii=False)))
                self._cur_level = "OK"
                self._last_emit_ts = time.time()

        self._prev = snap
        return out
