from __future__ import annotations

import threading
import time
import typer

from argus import db
from argus.collectors.authlog import tail_file
from argus.collectors.temperature import read_cpu_temp_c
from argus.collectors.memory import snapshot as memory_snapshot
from argus.detectors.hea_disk import DiskUsageDetector
from argus.detectors.hea_services import HeaServicesDetector
from argus.detectors.hea_temperature import TemperatureDetector
from argus.detectors.hea_memory import MemoryPressureDetector
from argus.detectors.sec01_ssh import SshBruteForceDetector
from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
from argus.detectors.sec03_sudo import SudoActivityDetector
from argus.detectors.sec04_listen import ListeningPortDetector
from argus.detectors.sec05_file_integrity import FileIntegrityDetector


def _sec04_loop(stop: threading.Event, interval_s: int = 30) -> None:
    det = ListeningPortDetector()

    # baseline (no events)
    det.poll()

    while not stop.is_set():
        try:
            for sev, entity, msg in det.poll():
                db.add_event(code="SEC-04", severity=sev, message=msg, entity=entity)
                typer.echo(f"[SEC-04] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[SEC-04] ERROR    listen-scan failed: {e!r}")

        stop.wait(interval_s)


def _sec05_loop(stop: threading.Event, interval_s: int = 10) -> None:
    det = FileIntegrityDetector()

    # baseline (no events)
    det.poll()

    while not stop.is_set():
        try:
            for sev, entity, msg in det.poll():
                db.add_event(code="SEC-05", severity=sev, message=msg, entity=entity)
                typer.echo(f"[SEC-05] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[SEC-05] ERROR    integrity-scan failed: {e!r}")

        stop.wait(interval_s)


def _hea_temp_loop(stop: threading.Event, interval_s: int = 5) -> None:
    det = TemperatureDetector()

    while not stop.is_set():
        try:
            t = read_cpu_temp_c()
            if t is not None:
                for code, sev, entity, msg in det.poll(t):
                    db.add_event(code=code, severity=sev, message=msg, entity=entity)
                    typer.echo(f"[{code}] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[HEA-TEMP] ERROR    temp-scan failed: {e!r}")

        stop.wait(interval_s)


def _hea03_loop(stop: threading.Event, interval_s: int = 30) -> None:
    det = DiskUsageDetector()

    # prime poll (no events)
    det.poll()

    while not stop.is_set():
        try:
            for item in det.poll():
                # item can be (sev, entity, msg, details_json)
                sev, entity, msg, details_json = item
                db.add_event(
                    code="HEA-03",
                    severity=sev,
                    message=msg,
                    entity=str(entity),
                    details_json=details_json,
                )
                typer.echo(f"[HEA-03] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[HEA-03] ERROR    disk-scan failed: {e!r}")

        stop.wait(interval_s)


def _hea04_loop(stop: threading.Event, interval_s: int = 1) -> None:
    """
    HEA-04: systemd service health.
    Called frequently, detector internally rate-limits.
    """
    det = HeaServicesDetector(interval_s=15)

    # baseline if detector supports it
    if hasattr(det, "poll"):
        try:
            _ = list(det.poll())  # type: ignore[attr-defined]
        except Exception:
            pass

    while not stop.is_set():
        try:
            if hasattr(det, "poll"):
                for item in det.poll():  # type: ignore[attr-defined]
                    # accepted shapes:
                    #   (sev, entity, msg)
                    #   (code, sev, entity, msg)
                    if not item:
                        continue
                    if len(item) == 3:
                        sev, entity, msg = item
                        code = "HEA-04"
                    elif len(item) >= 4:
                        code, sev, entity, msg = item[0], item[1], item[2], item[3]
                    else:
                        continue

                    db.add_event(code=str(code), severity=str(sev), message=str(msg), entity=str(entity))
                    typer.echo(f"[{code}] {str(sev):<8} {entity}  {msg}")
            else:
                now_ts = int(time.time())
                det.tick(now_ts)  # type: ignore[attr-defined]
        except Exception as e:
            typer.echo(f"[HEA-04] ERROR    service-scan failed: {e!r}")

        stop.wait(interval_s)


def _hea05_loop(stop: threading.Event, interval_s: int = 5) -> None:
    """
    HEA-05: Memory pressure (MemAvailable + swap thrashing)
    """
    det = MemoryPressureDetector()

    # baseline (no events)
    try:
        det.poll(memory_snapshot())
    except Exception:
        pass

    while not stop.is_set():
        try:
            snap = memory_snapshot()
            for sev, entity, msg, details_json in det.poll(snap):
                db.add_event(
                    code="HEA-05",
                    severity=sev,
                    message=msg,
                    entity=str(entity),
                    details_json=details_json,
                )
                typer.echo(f"[HEA-05] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[HEA-05] ERROR    memory-scan failed: {e!r}")

        stop.wait(interval_s)


def run_authlog_security(log_path: str = "/var/log/auth.log") -> None:
    """
    Foreground monitor:
      - tail auth.log -> SEC-01/02/03
      - background poll threads -> SEC-04, SEC-05, HEA-01/02, HEA-03, HEA-04, HEA-05
    """
    db.init_db()

    det_sec01 = SshBruteForceDetector()
    det_sec02 = SshSuccessAfterFailsDetector()
    det_sec03 = SudoActivityDetector()

    detectors = [
        ("SEC-01", det_sec01),
        ("SEC-02", det_sec02),
        ("SEC-03", det_sec03),
    ]

    typer.echo(f"[argus] Monitor: auth.log -> {log_path}")
    typer.echo("[argus] Premi CTRL+C per fermare.")

    stop = threading.Event()

    t_sec04 = threading.Thread(target=_sec04_loop, args=(stop,), daemon=True)
    t_sec05 = threading.Thread(target=_sec05_loop, args=(stop,), daemon=True)
    t_temp  = threading.Thread(target=_hea_temp_loop, args=(stop,), daemon=True)
    t_disk  = threading.Thread(target=_hea03_loop, args=(stop,), daemon=True)
    t_svc   = threading.Thread(target=_hea04_loop, args=(stop,), daemon=True)
    t_mem   = threading.Thread(target=_hea05_loop, args=(stop,), daemon=True)

    t_sec04.start()
    t_sec05.start()
    t_temp.start()
    t_disk.start()
    t_svc.start()
    t_mem.start()

    time.sleep(0.2)

    try:
        for line in tail_file(log_path, from_end=True):
            for code, det in detectors:
                try:
                    res = det.handle_line(line)
                except Exception as e:
                    typer.echo(f"[{code}] ERROR    detector failed: {e!r}")
                    continue

                if not res:
                    continue

                severity, entity, message = res
                db.add_event(code=code, severity=severity, message=message, entity=str(entity))
                typer.echo(f"[{code}] {severity:<8} {entity}  {message}")

    except PermissionError:
        typer.echo(f"[argus] Permesso negato su {log_path}.")
        typer.echo("[argus] Soluzione tipica su Ubuntu: aggiungi l'utente al gruppo 'adm':")
        typer.echo("        sudo usermod -aG adm $USER")
        typer.echo("        poi fai logout/login (o riavvia).")
        raise
    except KeyboardInterrupt:
        typer.echo("\n[argus] Stop richiesto dall'utente. (CTRL+C)")
    finally:
        stop.set()
        t_sec04.join(timeout=2)
        t_sec05.join(timeout=2)
        t_temp.join(timeout=2)
        t_disk.join(timeout=2)
        t_svc.join(timeout=2)
        t_mem.join(timeout=2)
