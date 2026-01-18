from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

CONFIG_PATH = Path.home() / ".config" / "argus" / "config.yaml"


def _ensure_config_dir() -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_config() -> Dict[str, Any]:
    _ensure_config_dir()
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def save_config(cfg: Dict[str, Any]) -> None:
    _ensure_config_dir()
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)


def _sec04_list(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    sec = cfg.setdefault("security", {})
    if not isinstance(sec, dict):
        sec = {}
        cfg["security"] = sec
    al = sec.setdefault("sec04_trust", [])
    if not isinstance(al, list):
        al = []
        sec["sec04_trust"] = al
    return al


def is_sec04_trusted(proc: str, port: int, bind: str) -> bool:
    cfg = load_config()
    al = _sec04_list(cfg)
    for e in al:
        if not isinstance(e, dict):
            continue
        if str(e.get("proc", "")).lower() == proc.lower() and int(e.get("port", -1)) == int(port) and str(e.get("bind", "")).upper() == bind.upper():
            return True
    return False


def add_sec04_trust(proc: str, port: int, bind: str) -> Tuple[bool, str]:
    cfg = load_config()
    al = _sec04_list(cfg)

    entry = {"proc": proc, "port": int(port), "bind": bind.upper()}
    for e in al:
        if isinstance(e, dict) and e.get("proc") == entry["proc"] and int(e.get("port", -1)) == entry["port"] and str(e.get("bind", "")).upper() == entry["bind"]:
            return (False, f"Già trusted: {proc} port={port} bind={bind}")

    al.append(entry)
    save_config(cfg)
    return (True, f"Trusted aggiunto: {proc} port={port} bind={bind}")
