from __future__ import annotations

import sqlite3
import time
from typing import Optional, Tuple, List, Dict, Any

from argus import paths


def _now() -> int:
    return int(time.time())


def connect() -> sqlite3.Connection:
    """Connessione SQLite al DB di Argus."""
    paths.ensure_dirs()
    conn = sqlite3.connect(paths.db_file())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Crea tabelle v1 se non esistono."""
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_flags (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                code TEXT,
                severity TEXT,
                message TEXT,
                entity TEXT,
                details_json TEXT,
                report_md_path TEXT,
                report_json_path TEXT,
                is_active INTEGER DEFAULT 0,
                ended_ts INTEGER
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS first_seen (
                key TEXT PRIMARY KEY,
                first_ts INTEGER NOT NULL,
                last_ts INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 1
            )
            """
        )

        conn.commit()


# -------------------------
# Runtime flags (state/mute/maintenance)
# -------------------------
def set_flag(key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
    """Imposta una flag con scadenza opzionale."""
    expires_at = _now() + ttl_seconds if ttl_seconds is not None else None
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO runtime_flags(key, value, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                expires_at=excluded.expires_at
            """,
            (key, value, expires_at),
        )
        conn.commit()


def get_flag(key: str) -> Optional[Tuple[str, Optional[int]]]:
    """
    Ritorna (value, expires_at) oppure None.
    Se la flag è scaduta, la elimina e ritorna None.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT value, expires_at FROM runtime_flags WHERE key = ?",
            (key,),
        ).fetchone()

        if row is None:
            return None

        value = str(row["value"])
        expires_at = row["expires_at"]

        if expires_at is not None and int(expires_at) <= _now():
            conn.execute("DELETE FROM runtime_flags WHERE key = ?", (key,))
            conn.commit()
            return None

        return value, (int(expires_at) if expires_at is not None else None)


def clear_flag(key: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM runtime_flags WHERE key = ?", (key,))
        conn.commit()


def remaining_seconds(key: str) -> Optional[int]:
    """Secondi rimanenti per una flag con scadenza. None se non esiste o senza expiry."""
    data = get_flag(key)
    if data is None:
        return None
    _, expires_at = data
    if expires_at is None:
        return None
    return max(0, int(expires_at) - _now())


# -------------------------
# Events (feed)
# -------------------------
def add_event(
    code: str,
    severity: str,
    message: str,
    entity: str = "",
    details_json: str = "",
    is_active: int = 0,
) -> int:
    """
    Inserisce un evento in tabella events.
    Ritorna l'id dell'evento inserito.
    """
    init_db()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO events(ts, code, severity, message, entity, details_json, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (_now(), code, severity, message, entity, details_json, is_active),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_events(limit: int = 10) -> List[Dict[str, Any]]:
    """Ritorna gli ultimi N eventi (più recenti prima)."""
    init_db()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, code, severity, message, entity, is_active, ended_ts
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def clear_events() -> None:
    """Pulisce completamente la tabella events (solo per demo/test)."""
    init_db()
    with connect() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


# -------------------------
# First seen (novità / dedupe)
# -------------------------
def first_seen_touch(key: str) -> bool:
    """
    Registra la chiave in first_seen.
    Ritorna True se è la prima volta che la vediamo (NEW),
    False se era già presente (già visto).
    """
    init_db()
    now = _now()
    with connect() as conn:
        row = conn.execute(
            "SELECT key FROM first_seen WHERE key = ?",
            (key,),
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO first_seen(key, first_ts, last_ts, count) VALUES (?, ?, ?, 1)",
                (key, now, now),
            )
            conn.commit()
            return True

        conn.execute(
            "UPDATE first_seen SET last_ts = ?, count = count + 1 WHERE key = ?",
            (now, key),
        )
        conn.commit()
        return False


def list_first_seen(prefix: str, since_ts: int, limit: int = 10):
    """
    Lista le chiavi first_seen che iniziano con prefix e con first_ts >= since_ts.
    Ritorna dict con key, first_ts, last_ts, count.
    """
    init_db()
    like = f"{prefix}%"
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT key, first_ts, last_ts, count
            FROM first_seen
            WHERE key LIKE ? AND first_ts >= ?
            ORDER BY first_ts DESC
            LIMIT ?
            """,
            (like, since_ts, limit),
        ).fetchall()
        return [dict(r) for r in rows]
