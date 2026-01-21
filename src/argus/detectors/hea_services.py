from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from argus import db
from argus.collectors.services import ServiceState, probe_existing, read_states


@dataclass(frozen=True)
class ServiceSpec:
    unit: str
    base_severity: str          # "WARNING" or "CRITICAL"
    only_if_enabled: bool       # if True, alert only if enabled/static


_ENABLED_STATES = {
    "enabled",
    "enabled-runtime",
    "static",
    "alias",
    "generated",
    "indirect",
}


def _is_enabled(unit_file_state: str) -> bool:
    return (unit_file_state or "").strip().lower() in _ENABLED_STATES


def _pick_first(candidates: List[str]) -> Optional[str]:
    existing = probe_existing(candidates)
    return existing[0] if existing else None


def default_specs() -> Dict[str, ServiceSpec]:
    """
    Chosen defaults:
    - core: always expected ON (CRITICAL)
    - useful: alert only if enabled/static (WARNING, escalates to CRITICAL on failed)
    Auto-picks first existing in each family.
    """
    specs: Dict[str, ServiceSpec] = {}

    # Core (almost always expected running on systemd machines)
    for unit in ("systemd-journald.service", "dbus.service", "systemd-logind.service"):
        u = _pick_first([unit])
        if u:
            specs[u] = ServiceSpec(u, "CRITICAL", only_if_enabled=False)

    # Networking + DNS (critical-ish)
    u = _pick_first(["NetworkManager.service", "systemd-networkd.service"])
    if u:
        specs[u] = ServiceSpec(u, "CRITICAL", only_if_enabled=False)

    u = _pick_first(["systemd-resolved.service"])
    if u:
        # DNS down is a big deal, but keep base WARNING (failed => CRITICAL)
        specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=False)

    # Scheduler (only if enabled)
    u = _pick_first(["cron.service", "crond.service"])
    if u:
        specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=True)

    # SSH (only if enabled)
    u = _pick_first(["ssh.service", "sshd.service"])
    if u:
        specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=True)

    # Time sync (only if enabled)
    u = _pick_first(["chronyd.service", "systemd-timesyncd.service"])
    if u:
        specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=True)

    # Firewall (only if enabled)
    u = _pick_first(["ufw.service", "firewalld.service"])
    if u:
        specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=True)

    # Security extras (only if enabled)
    for unit in ("fail2ban.service", "auditd.service", "rsyslog.service"):
        u = _pick_first([unit])
        if u:
            specs[u] = ServiceSpec(u, "WARNING", only_if_enabled=True)

    return specs


class HeaServicesDetector:
    def __init__(self, interval_s: int = 15) -> None:
        self.interval_s = max(5, int(interval_s))
        self._next_ts: int = 0
        self._specs: Dict[str, ServiceSpec] = default_specs()
        self._streak: Dict[str, int] = {u: 0 for u in self._specs}
        self._is_bad: Dict[str, bool] = {u: False for u in self._specs}

    def _eval(self, st: ServiceState, spec: ServiceSpec) -> Tuple[bool, str, str]:
        """
        Returns: (unhealthy, reason, severity)
        reason: "failed" | "inactive" | ""
        severity: "WARNING" | "CRITICAL"
        """
        active = (st.active or "").lower()
        sub = (st.sub or "").lower()
        ufs = (st.unit_file_state or "").lower()

        enabled = _is_enabled(ufs)

        if spec.only_if_enabled and not enabled:
            return (False, "", "INFO")

        # healthy-ish/transient
        if active in ("active", "activating", "deactivating", "reloading"):
            return (False, "", "INFO")

        # hard fail
        if active == "failed" or sub == "failed":
            return (True, "failed", "CRITICAL")

        # inactive when expected
        if active in ("inactive", "dead"):
            # if it's enabled/static (or core), treat as unhealthy
            if enabled or not spec.only_if_enabled:
                sev = "CRITICAL" if spec.base_severity == "CRITICAL" else "WARNING"
                return (True, "inactive", sev)

        return (False, "", "INFO")

    def tick(self, now_ts: int) -> None:
        if now_ts < self._next_ts:
            return
        self._next_ts = now_ts + self.interval_s

        units = list(self._specs.keys())
        if not units:
            return

        states = read_states(units)
        if not states:
            return

        for unit, spec in self._specs.items():
            st = states.get(unit)
            if not st or (st.load or "").lower() == "not-found":
                continue

            unhealthy, reason, sev = self._eval(st, spec)

            if unhealthy:
                self._streak[unit] = self._streak.get(unit, 0) + 1
            else:
                self._streak[unit] = 0
                self._is_bad[unit] = False
                continue

            # debounce: require 2 consecutive bad checks
            if self._streak[unit] < 2:
                continue

            if self._is_bad.get(unit, False):
                continue  # already reported

            self._is_bad[unit] = True

            status = st.exec_main_status if st.exec_main_status is not None else "-"
            restarts = st.nrestarts if st.nrestarts is not None else "-"
            msg = (
                f"Service unhealthy: {unit} "
                f"(active={st.active}, sub={st.sub}, state={st.unit_file_state}, "
                f"result={st.result or '-'}, status={status}, restarts={restarts})."
            )
            db.add_event(code="HEA-04", severity=sev, message=msg, entity=unit)
