from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator


def tail_file(path: str, from_end: bool = True, poll_interval: float = 0.25) -> Iterator[str]:
    """
    Segue un file tipo `tail -F` (versione semplice v1).
    - from_end=True: parte dalla fine (solo nuovi eventi)
    - poll_interval: quanto spesso controllare nuove righe
    """
    p = Path(path)

    # Apriamo il file (errors='replace' evita crash su caratteri strani)
    with p.open("r", encoding="utf-8", errors="replace") as f:
        if from_end:
            f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line.rstrip("\n")
