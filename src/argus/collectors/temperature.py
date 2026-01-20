from __future__ import annotations

from pathlib import Path
from typing import Optional

# Cache best sensor path (best-effort)
_CACHED_TEMP_PATH: Optional[Path] = None


def _read_int(path: Path) -> Optional[int]:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _pick_best_thermal_zone() -> Optional[Path]:
    """
    Best-effort: pick a good thermal_zone*/temp for CPU/package.
    Works on many distros; if not available, returns None.
    """
    base = Path("/sys/class/thermal")
    if not base.exists():
        return None

    zones = sorted(base.glob("thermal_zone*"))
    if not zones:
        return None

    best: Optional[Path] = None
    best_score = -1

    for z in zones:
        tp = z / "temp"
        typ = z / "type"
        if not tp.exists():
            continue

        tname = (typ.read_text(encoding="utf-8").strip().lower() if typ.exists() else "")
        score = 0

        # Prefer CPU/package-like zones
        if "x86_pkg_temp" in tname or "pkg" in tname or "package" in tname:
            score += 50
        if "cpu" in tname:
            score += 40
        if "soc" in tname:
            score += 25
        if "acpitz" in tname:
            score += 5  # often exists but not ideal

        # Sanity check: value should be plausible
        val = _read_int(tp)
        if val is None:
            continue
        c = val / 1000.0 if val > 1000 else float(val)
        if 0.0 <= c <= 120.0:
            score += 10
        else:
            score -= 50

        if score > best_score:
            best_score = score
            best = tp

    return best


def read_cpu_temp_c() -> Optional[float]:
    """
    Returns CPU temp in Celsius (best-effort). None if not available.
    """
    global _CACHED_TEMP_PATH

    if _CACHED_TEMP_PATH is None:
        _CACHED_TEMP_PATH = _pick_best_thermal_zone()

    if _CACHED_TEMP_PATH is None:
        return None

    v = _read_int(_CACHED_TEMP_PATH)
    if v is None:
        return None

    # Many sysfs temps are millidegrees (e.g., 42000)
    c = v / 1000.0 if v > 1000 else float(v)
    if not (0.0 <= c <= 120.0):
        return None
    return c


def format_cpu_temp() -> str:
    t = read_cpu_temp_c()
    return "--°C" if t is None else f"{int(round(t))}°C"
