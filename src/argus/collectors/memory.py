from __future__ import annotations

import os
import time
from typing import Any, Dict, List


def _read_meminfo() -> Dict[str, int]:
    """
    Parse /proc/meminfo, return values in kB when possible.
    Keys we care about: MemTotal, MemAvailable, SwapTotal, SwapFree
    """
    out: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                k, rest = line.split(":", 1)
                rest = rest.strip()
                parts = rest.split()
                if not parts:
                    continue
                # usually: "<num> kB"
                try:
                    out[k] = int(parts[0])
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _read_vmstat() -> Dict[str, int]:
    """
    Parse /proc/vmstat counters (pages).
    Keys we care about: pswpin, pswpout
    """
    out: Dict[str, int] = {}
    try:
        with open("/proc/vmstat", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) != 2:
                    continue
                k, v = parts
                if k in ("pswpin", "pswpout"):
                    try:
                        out[k] = int(v)
                    except Exception:
                        pass
    except Exception:
        pass
    return out


def snapshot() -> Dict[str, Any]:
    """
    Lightweight memory snapshot.

    Returns:
      {
        "ts": float,
        "mem_total_kb": int,
        "mem_available_kb": int,
        "swap_total_kb": int,
        "swap_free_kb": int,
        "pswpin": int,     # pages counter
        "pswpout": int,    # pages counter
      }
    """
    mi = _read_meminfo()
    vm = _read_vmstat()

    mem_total = int(mi.get("MemTotal", 0))
    mem_avail = int(mi.get("MemAvailable", 0))
    swap_total = int(mi.get("SwapTotal", 0))
    swap_free = int(mi.get("SwapFree", 0))

    return {
        "ts": time.time(),
        "mem_total_kb": mem_total,
        "mem_available_kb": mem_avail,
        "swap_total_kb": swap_total,
        "swap_free_kb": swap_free,
        "pswpin": int(vm.get("pswpin", 0)),
        "pswpout": int(vm.get("pswpout", 0)),
    }


def _read_status_rss_kb(pid: str) -> tuple[str, int]:
    """
    Read /proc/<pid>/status for Name and VmRSS.
    Returns (name, rss_kb). If not available -> ("", 0)
    """
    name = ""
    rss_kb = 0
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("VmRSS:"):
                    # example: "VmRSS:   123456 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            rss_kb = int(parts[1])
                        except Exception:
                            rss_kb = 0
    except Exception:
        return ("", 0)
    return (name, rss_kb)


def _read_cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        if not raw:
            return ""
        # cmdline is NUL-separated
        s = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        return s
    except Exception:
        return ""


def top_rss_processes(limit: int = 3) -> List[Dict[str, Any]]:
    """
    Best-effort "top RSS" list.
    Returned dict keys:
      pid, name, rss_kb, cmdline
    """
    items: List[Dict[str, Any]] = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            name, rss_kb = _read_status_rss_kb(pid)
            if rss_kb <= 0:
                continue
            cmd = _read_cmdline(pid)
            items.append(
                {
                    "pid": int(pid),
                    "name": name or "?",
                    "rss_kb": int(rss_kb),
                    "cmdline": cmd,
                }
            )
    except Exception:
        return []

    items.sort(key=lambda x: int(x.get("rss_kb", 0)), reverse=True)
    return items[: max(1, int(limit))]
