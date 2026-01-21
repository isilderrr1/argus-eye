from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class ServiceState:
    unit: str
    load: str
    active: str
    sub: str
    unit_file_state: str
    result: str
    exec_main_status: Optional[int]
    nrestarts: Optional[int]


def _run_systemctl(args: List[str], timeout: float = 2.0) -> str:
    try:
        r = subprocess.run(
            ["systemctl", "--no-pager", "--plain", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # systemctl may return non-zero for missing units, but stdout can still contain blocks
        return r.stdout or ""
    except Exception:
        return ""


def read_states(units: Iterable[str]) -> Dict[str, ServiceState]:
    units = [u for u in units if u]
    if not units:
        return {}

    props = [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "Result",
        "ExecMainStatus",
        "NRestarts",
    ]
    args = ["show"] + [f"-p{p}" for p in props] + units
    out = _run_systemctl(args, timeout=2.5)
    if not out.strip():
        return {}

    def _to_int(s: str) -> Optional[int]:
        try:
            return int(s)
        except Exception:
            return None

    states: Dict[str, ServiceState] = {}
    blocks = [b for b in out.split("\n\n") if b.strip()]
    for b in blocks:
        kv: Dict[str, str] = {}
        for line in b.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()

        unit = kv.get("Id", "").strip()
        if not unit:
            continue

        states[unit] = ServiceState(
            unit=unit,
            load=kv.get("LoadState", "").strip(),
            active=kv.get("ActiveState", "").strip(),
            sub=kv.get("SubState", "").strip(),
            unit_file_state=kv.get("UnitFileState", "").strip(),
            result=kv.get("Result", "").strip(),
            exec_main_status=_to_int(kv.get("ExecMainStatus", "").strip()),
            nrestarts=_to_int(kv.get("NRestarts", "").strip()),
        )

    return states


def probe_existing(candidates: Iterable[str]) -> List[str]:
    cands = [c for c in candidates if c]
    if not cands:
        return []

    st = read_states(cands)
    out: List[str] = []
    for c in cands:
        s = st.get(c)
        if not s:
            continue
        if (s.load or "").lower() != "not-found":
            out.append(c)
    return out
