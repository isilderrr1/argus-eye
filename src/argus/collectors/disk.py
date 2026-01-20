from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Set, Tuple, Optional


IGNORE_FSTYPES: Set[str] = {
    "tmpfs",
    "devtmpfs",
    "squashfs",
    "overlay",
    "ramfs",
}


@dataclass(frozen=True)
class MountUsage:
    mount: str
    fstype: str
    total_bytes: int
    used_bytes: int
    used_pct: int


def _statvfs_usage(path: str) -> Tuple[int, int, int]:
    st = os.statvfs(path)
    total = int(st.f_frsize) * int(st.f_blocks)
    avail = int(st.f_frsize) * int(st.f_bavail)
    used = max(0, total - avail)
    pct = int(round((used * 100) / total)) if total > 0 else 0
    return total, used, pct


def list_mount_usage(min_total_bytes: int = 1 << 30) -> List[MountUsage]:
    """Lista mount utili (filtrati) con percentuale used."""
    mounts: List[MountUsage] = []
    seen: Set[str] = set()

    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount = parts[1]
                fstype = parts[2]

                if mount in seen:
                    continue
                seen.add(mount)

                if fstype in IGNORE_FSTYPES:
                    continue

                # mountpoint valido?
                if not os.path.isdir(mount):
                    continue

                try:
                    total, used, pct = _statvfs_usage(mount)
                except OSError:
                    continue

                if total < min_total_bytes:
                    continue

                mounts.append(MountUsage(mount=mount, fstype=fstype, total_bytes=total, used_bytes=used, used_pct=pct))
    except Exception:
        return []

    # '/' prima, poi alfabetico
    mounts.sort(key=lambda m: (m.mount != "/", m.mount))
    return mounts


def root_used_pct() -> Optional[int]:
    try:
        return _statvfs_usage("/")[2]
    except Exception:
        return None


def fmt_gb(n: int) -> str:
    return f"{n / (1024**3):.1f}GB"
