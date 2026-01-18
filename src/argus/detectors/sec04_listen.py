from __future__ import annotations

import re
import socket
import subprocess
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Set, Tuple

from argus import db
from argus.trust import is_sec04_trusted


SENSITIVE_PORTS = {22, 23, 3389, 5900, 445, 139, 3306, 5432, 6379, 9200}

LAN_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("100.64.0.0/10"),
    ip_network("169.254.0.0/16"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

RE_PROC = re.compile(r'users:\(\("([^"]+)"')


@dataclass(frozen=True)
class Key:
    proc: str
    port: int
    proto: str   # tcp/udp
    bind: str    # LOCAL/LAN/GLOBAL


def _now() -> int:
    return int(time.time())


def _parse_host_port(local: str) -> Optional[Tuple[str, int]]:
    # esempi: "127.0.0.1:631" , "*:22" , "[::]:22"
    if not local:
        return None
    if local.startswith("[") and "]" in local:
        host = local[1:local.rfind("]")]
        rest = local[local.rfind("]") + 1 :]
        if not rest.startswith(":"):
            return None
        port_s = rest[1:]
    else:
        if ":" not in local:
            return None
        host, port_s = local.rsplit(":", 1)

    if not port_s.isdigit():
        return None
    return host, int(port_s)


def _service_name(port: int, proto: str) -> str:
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return "unknown"


def _bind_type(host: str) -> str:
    h = (host or "").strip().lower()

    if h in ("127.0.0.1", "::1", "localhost"):
        return "LOCAL"
    if h in ("*", "0.0.0.0", "::"):
        return "GLOBAL"

    try:
        ip = ip_address(host)
        if ip.is_loopback:
            return "LOCAL"
        for net in LAN_NETS:
            if ip in net:
                return "LAN"
        if getattr(ip, "is_private", False):
            return "LAN"
        return "GLOBAL"
    except Exception:
        return "LAN"


def _severity(bind: str, port: int) -> str:
    if bind == "LOCAL":
        return "INFO"
    if bind == "LAN":
        return "WARNING"
    # GLOBAL:
    return "CRITICAL" if port in SENSITIVE_PORTS else "WARNING"


class ListeningPortDetector:
    """
    SEC-04 — Nuovo servizio/porta in ascolto (spec-perfect)
    - baseline all'avvio (non emette nulla)
    - durata minima: presente >= 60s
    - first-seen 7 giorni (prune)
    - severità: LOCAL=INFO, LAN=WARNING, GLOBAL=CRIT solo se porta sensibile
    - trust allowlist: (proc,port,bind) => suppress
    """

    MIN_DURATION_S = 60
    RETENTION_S = 7 * 24 * 3600

    def __init__(self) -> None:
        self._primed = False
        self._seen_session: Set[Key] = set()
        self._pending_since: Dict[Key, int] = {}
        self._last_host: Dict[Key, str] = {}
        self._last_prune_ts = 0

    def _snapshot(self) -> Dict[Key, str]:
        """
        Ritorna mapping Key -> host "migliore" visto ora.
        Prova ss con processi (-p). Se non disponibile, proc='unknown'.
        """
        cmd = ["ss", "-H", "-lntup"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = res.stdout.splitlines() if res.stdout else []

        snap: Dict[Key, str] = {}

        for line in out:
            parts = line.split()
            if len(parts) < 6:
                continue

            proto = parts[0].lower()
            if proto not in ("tcp", "udp"):
                continue

            local = parts[4]
            hp = _parse_host_port(local)
            if not hp:
                continue
            host, port = hp

            m = RE_PROC.search(line)
            proc = m.group(1) if m else "unknown"

            bind = _bind_type(host)
            k = Key(proc=proc, port=port, proto=proto, bind=bind)

            # scegliamo un host preferito (se passa da 127.0.0.1 a 0.0.0.0, preferiamo quello più "ampio")
            if k not in snap:
                snap[k] = host
            else:
                prev = snap[k].lower()
                curr = host.lower()
                # preferisci GLOBAL wildcard se presente
                if curr in ("0.0.0.0", "::", "*") and prev not in ("0.0.0.0", "::", "*"):
                    snap[k] = host

        return snap

    def _prune_if_needed(self) -> None:
        now = _now()
        # prune massimo ogni 10 minuti
        if now - self._last_prune_ts < 600:
            return
        cutoff = now - self.RETENTION_S
        db.prune_first_seen(prefix="sec04|", older_than_ts=cutoff)
        self._last_prune_ts = now

    def poll(self) -> List[Tuple[str, str, str]]:
        self._prune_if_needed()

        snap = self._snapshot()
        keys_now = set(snap.keys())

        # baseline: memorizza cosa già era in ascolto, niente eventi
        if not self._primed:
            self._seen_session = set(keys_now)
            self._primed = True
            return []

        now = _now()
        events: List[Tuple[str, str, str]] = []

        # pending cleanup: se è sparito prima dei 60s, lo rimuoviamo
        for k in list(self._pending_since.keys()):
            if k not in keys_now:
                self._pending_since.pop(k, None)
                self._last_host.pop(k, None)

        for k in keys_now:
            # già visto in questa sessione -> niente
            if k in self._seen_session:
                continue

            # avvia timer di stabilità
            if k not in self._pending_since:
                self._pending_since[k] = now
                self._last_host[k] = snap.get(k, "unknown")
                continue

            # aggiorna host “ultimo visto”
            self._last_host[k] = snap.get(k, self._last_host.get(k, "unknown"))

            # non è ancora stabile 60s
            if now - self._pending_since[k] < self.MIN_DURATION_S:
                continue

            # è stabile: ora lo consideriamo “nuovo” nella sessione
            self._seen_session.add(k)
            self._pending_since.pop(k, None)

            host = self._last_host.pop(k, "unknown")

            # TRUST: se allowlisted, non emettiamo (e non scriviamo first_seen)
            if is_sec04_trusted(k.proc, k.port, k.bind):
                continue

            # first-seen DB (7 giorni via prune)
            fs_key = f"sec04|{k.proc}|{k.port}|{k.proto}|{k.bind}"
            is_new = db.first_seen_touch(fs_key)
            if not is_new:
                continue

            sev = _severity(k.bind, k.port)
            svc = _service_name(k.port, k.proto)

            entity = f"{host}:{k.port}"
            if sev == "INFO":
                msg = f"Nuovo servizio locale: {k.proc} su {host}:{k.port}/{k.proto} (service={svc})."
            elif sev == "WARNING":
                msg = f"Nuovo servizio in rete: {k.proc} su {host}:{k.port}/{k.proto} (service={svc})."
            else:
                msg = f"Porta esposta: {k.proc} su {host}:{k.port}/{k.proto} (service={svc})."

            msg += f" [{k.bind}] [NEW]"
            events.append((sev, entity, msg))

        return events
