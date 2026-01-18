from __future__ import annotations

import threading
import time
import typer

from argus import db
from argus.collectors.authlog import tail_file
from argus.detectors.sec01_ssh import SshBruteForceDetector
from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
from argus.detectors.sec03_sudo import SudoActivityDetector
from argus.detectors.sec04_listen import ListeningPortDetector
from argus.detectors.sec05_file_integrity import FileIntegrityDetector


def _sec04_loop(stop: threading.Event, interval_s: int = 15) -> None:
    det = ListeningPortDetector()

    # baseline (niente eventi)
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

    # baseline (niente eventi)
    det.poll()

    while not stop.is_set():
        try:
            for sev, entity, msg in det.poll():
                db.add_event(code="SEC-05", severity=sev, message=msg, entity=entity)
                typer.echo(f"[SEC-05] {sev:<8} {entity}  {msg}")
        except Exception as e:
            typer.echo(f"[SEC-05] ERROR    integrity-scan failed: {e!r}")

        stop.wait(interval_s)


def run_authlog_security(log_path: str = "/var/log/auth.log") -> None:
    """
    Monitor foreground:
      - tail auth.log -> SEC-01/02/03
      - thread poll -> SEC-04
      - thread poll -> SEC-05
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

    typer.echo(f"[argus] Security monitor (auth.log) -> {log_path}")
    typer.echo("[argus] Premi CTRL+C per fermare.")

    stop = threading.Event()
    t4 = threading.Thread(target=_sec04_loop, args=(stop,), daemon=True)
    t5 = threading.Thread(target=_sec05_loop, args=(stop,), daemon=True)
    t4.start()
    t5.start()

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
        t4.join(timeout=2)
        t5.join(timeout=2)
