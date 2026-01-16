from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import yaml

from argus import paths


@dataclass(frozen=True)
class ArgusConfig:
    # Regola globale: popup solo eventi CRITICAL
    popup_mode: str = "CRITICAL_ONLY"

    # Soglie temperatura v1
    temp_warn_c: int = 85
    temp_crit_c: int = 95


DEFAULT_CONFIG = ArgusConfig()


def _to_dict(cfg: ArgusConfig) -> Dict[str, Any]:
    return {
        "popup_mode": cfg.popup_mode,
        "temp": {
            "warn_c": cfg.temp_warn_c,
            "crit_c": cfg.temp_crit_c,
        },
    }


def ensure_config_exists() -> None:
    """Crea config.yaml se non esiste, usando i default."""
    paths.ensure_dirs()
    cfg_path = paths.config_file()
    if cfg_path.exists():
        return

    cfg_path.write_text(
        yaml.safe_dump(_to_dict(DEFAULT_CONFIG), sort_keys=False),
        encoding="utf-8",
    )


def load_config() -> ArgusConfig:
    """Carica config.yaml e applica fallback sui default."""
    ensure_config_exists()
    raw = yaml.safe_load(paths.config_file().read_text(encoding="utf-8")) or {}

    popup_mode = raw.get("popup_mode", DEFAULT_CONFIG.popup_mode)
    temp = raw.get("temp", {}) or {}
    warn_c = int(temp.get("warn_c", DEFAULT_CONFIG.temp_warn_c))
    crit_c = int(temp.get("crit_c", DEFAULT_CONFIG.temp_crit_c))

    return ArgusConfig(
        popup_mode=popup_mode,
        temp_warn_c=warn_c,
        temp_crit_c=crit_c,
    )
