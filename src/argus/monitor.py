from __future__ import annotations

import time
import typer

from argus import db
from argus.collectors.authlog import tail_file
from argus.detectors.sec01_ssh import SshBruteForceDetector
from argus.detectors.sec02_ssh import SshSuccessAfterFailsDetector
from argus.detectors.sec03_sudo import SudoActivityDetector


def run_authlog_security(log_path: str = "/var/log/auth.log") -> None:
    """
    Monitor in foreground: legge auth.log in streaming e genera eventi security nel DB.
    Fermalo con CTRL+C.
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
    time.sleep(0.2)

    try:
        for line in tail_file(log_path, from_end=True):
            for code, det in detectors:
                res = det.handle_line(line)
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
