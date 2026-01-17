from __future__ import annotations

import time
import typer

from argus import db
from argus.collectors.authlog import tail_file
from argus.detectors.sec01_ssh import SshBruteForceDetector


def run_ssh_authlog(log_path: str = "/var/log/auth.log") -> None:
    """
    Monitor in foreground: legge auth.log in streaming e genera eventi SEC-01 nel DB.
    Fermalo con CTRL+C.
    """
    db.init_db()
    detector = SshBruteForceDetector()

    typer.echo(f"[argus] SEC-01 monitor (auth.log) -> {log_path}")
    typer.echo("[argus] Premi CTRL+C per fermare.")
    time.sleep(0.2)

    try:
        for line in tail_file(log_path, from_end=True):
            result = detector.handle_line(line)
            if not result:
                continue

            severity, ip, message = result
            db.add_event(code="SEC-01", severity=severity, message=message, entity=ip)
            typer.echo(f"[SEC-01] {severity:<8} {ip}  {message}")

    except PermissionError:
        typer.echo(f"[argus] Permesso negato su {log_path}.")
        typer.echo("[argus] Soluzione tipica su Ubuntu: aggiungi l'utente al gruppo 'adm':")
        typer.echo("        sudo usermod -aG adm $USER")
        typer.echo("        poi fai logout/login (o riavvia).")
        raise
    except KeyboardInterrupt:
        typer.echo("\n[argus] Stop richiesto dall'utente. (CTRL+C)")
