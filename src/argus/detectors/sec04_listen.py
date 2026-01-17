from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address
from typing import List, Optional, Set, Tuple

from argus import db


@dataclass(frozen=True)
class Listener:
    proto: str   # tcp / udp
    host: str    # 127.0.0.1, 0.0.0.0, ::, *
    port: int


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

    if port_s == "*" or not port_s.isdigit():
        return None
    return host, int(port_s)


def _service_name(port: int, proto: str) -> str:
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return "unknown"


def _severity_for_host(host: str) -> str:
    h = host.strip().lower()

    # wildcard / all interfaces
    if h in ("*", "0.0.0.0", "::"):
        return "CRITICAL"

    # loopback
    if h in ("127.0.0.1", "::1", "localhost"):
        return "INFO"

    # ip reale: private => LAN, public => CRITICAL
    try:
        ip = ip_address(host)
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            return "WARNING"
        return "CRITICAL"
    except Exception:
        # host non parsabile: trattiamolo prudenzialmente
        return "WARNING"


class ListeningPortDetector:
    """
    SEC-04: Nuova porta in ascolto.
    - Fa baseline all'avvio (nessun evento)
    - Poi emette solo se è first-seen "di sempre" (DB first_seen)
    """

    def __init__(self) -> None:
        self._primed: bool = False
        self._seen_session: Set[Listener] = set()

    def _snapshot(self) -> Set[Listener]:
        # ss -H -lntu : senza header, listen tcp/udp numerico
        res = subprocess.run(
            ["ss", "-H", "-lntu"],
            capture_output=True,
            text=True,
        )
        out = res.stdout.splitlines() if res.stdout else []
        snap: Set[Listener] = set()

        for line in out:
            parts = line.split()
            # atteso: netid state recvq sendq local peer ...
            if len(parts) < 6:
                continue
            proto = parts[0].lower()
            local = parts[4]

            hp = _parse_host_port(local)
            if not hp:
                continue
            host, port = hp
            if proto not in ("tcp", "udp"):
                continue

            snap.add(Listener(proto=proto, host=host, port=port))

        return snap

    def poll(self) -> List[Tuple[str, str, str]]:
        """
        Ritorna lista di eventi: (severity, entity, message)
        """
        snap = self._snapshot()

        # baseline: non emettiamo nulla, solo memorizziamo cosa era già aperto
        if not self._primed:
            self._seen_session = set(snap)
            self._primed = True
            return []

        events: List[Tuple[str, str, str]] = []

        for l in snap:
            if l in self._seen_session:
                continue

            # nuovo nella sessione -> segniamo subito
            self._seen_session.add(l)

            key = f"sec04|{l.proto}|{l.host}|{l.port}"
            is_new_ever = db.first_seen_touch(key)
            if not is_new_ever:
                # già visto in passato: per home-friendly non emettiamo
                continue

            sev = _severity_for_host(l.host)
            svc = _service_name(l.port, l.proto)
            entity = f"{l.proto}://{l.host}:{l.port}"
            msg = f"Nuova porta in ascolto: {entity} (service={svc}) [NEW]"

            events.append((sev, entity, msg))

        return events
