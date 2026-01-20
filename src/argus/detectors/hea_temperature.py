from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Tuple, Optional

EventOut = Tuple[str, str, str, str]  # (code, severity, entity, message)


@dataclass
class _Gate:
    start_ts: Optional[int] = None
    active: bool = False
    recover_ts: Optional[int] = None


class TemperatureDetector:
    """
    HEA-01:
      Trigger: CPU >= 85C for >= 30s (WARNING)
      Recover: <= 80C for >= 60s (INFO)

    HEA-02:
      Trigger: CPU >= 95C for >= 10s (CRITICAL)
      Recover: <= 90C for >= 60s (INFO)

    Emits events on state transitions only (no spam).
    """

    def __init__(self) -> None:
        self._hi = _Gate()
        self._crit = _Gate()

    def poll(self, temp_c: float, now: Optional[int] = None) -> List[EventOut]:
        n = int(now if now is not None else time.time())
        out: List[EventOut] = []

        # ---- CRITICAL gate (HEA-02) ----
        if not self._crit.active:
            if temp_c >= 95.0:
                if self._crit.start_ts is None:
                    self._crit.start_ts = n
                if (n - self._crit.start_ts) >= 10:
                    self._crit.active = True
                    self._crit.recover_ts = None
                    out.append((
                        "HEA-02",
                        "CRITICAL",
                        "cpu",
                        f"Critical CPU temperature: {int(round(temp_c))}°C (≥95°C for {n - self._crit.start_ts}s)."
                    ))
            else:
                self._crit.start_ts = None
        else:
            # recover when <= 90 for 60s
            if temp_c <= 90.0:
                if self._crit.recover_ts is None:
                    self._crit.recover_ts = n
                if (n - self._crit.recover_ts) >= 60:
                    self._crit.active = False
                    self._crit.start_ts = None
                    out.append((
                        "HEA-02",
                        "INFO",
                        "cpu",
                        f"CPU temperature recovered from critical range: {int(round(temp_c))}°C."
                    ))
            else:
                self._crit.recover_ts = None

        # ---- WARNING gate (HEA-01) ----
        # If critical is active, we suppress entering HEA-01 (keeps feed cleaner).
        if self._crit.active:
            # If HEA-01 was active already, let it recover normally (optional),
            # but we won't re-trigger it while critical is on.
            pass

        if not self._hi.active:
            if (not self._crit.active) and temp_c >= 85.0:
                if self._hi.start_ts is None:
                    self._hi.start_ts = n
                if (n - self._hi.start_ts) >= 30:
                    self._hi.active = True
                    self._hi.recover_ts = None
                    out.append((
                        "HEA-01",
                        "WARNING",
                        "cpu",
                        f"High CPU temperature: {int(round(temp_c))}°C (≥85°C for {n - self._hi.start_ts}s)."
                    ))
            else:
                self._hi.start_ts = None
        else:
            # recover when <= 80 for 60s
            if temp_c <= 80.0:
                if self._hi.recover_ts is None:
                    self._hi.recover_ts = n
                if (n - self._hi.recover_ts) >= 60:
                    self._hi.active = False
                    self._hi.start_ts = None
                    out.append((
                        "HEA-01",
                        "INFO",
                        "cpu",
                        f"CPU temperature back to normal: {int(round(temp_c))}°C."
                    ))
            else:
                self._hi.recover_ts = None

        return out
