from __future__ import annotations
from pathlib import Path


def config_dir() -> Path:
    """Cartella config utente (Linux standard)."""
    return Path.home() / ".config" / "argus"


def data_dir() -> Path:
    """Cartella dati/stato utente (Linux standard)."""
    return Path.home() / ".local" / "share" / "argus"


def reports_dir() -> Path:
    """Cartella report."""
    return data_dir() / "reports"


def ensure_dirs() -> None:
    """Crea tutte le cartelle necessarie."""
    config_dir().mkdir(parents=True, exist_ok=True)
    data_dir().mkdir(parents=True, exist_ok=True)
    reports_dir().mkdir(parents=True, exist_ok=True)


def config_file() -> Path:
    return config_dir() / "config.yaml"


def db_file() -> Path:
    return data_dir() / "argus.db"


def state_file() -> Path:
    # Temporaneo (lo sostituiremo con SQLite in Milestone 1c)
    return data_dir() / "state.txt"
