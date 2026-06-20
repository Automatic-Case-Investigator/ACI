"""SQLite-backed Findings Board store."""
from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

_lock = threading.Lock()
_DB_PATH = os.path.abspath(os.environ.get("BOARD_DB_PATH", "board.db"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS board_entries (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'fact',
                content TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'high',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        # dedup_key allows callers to collapse near-duplicate entries (e.g. the same
        # fact cited with different event ids). Added via ALTER for existing DBs.
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(board_entries)")}
        if "dedup_key" not in cols:
            conn.execute("ALTER TABLE board_entries ADD COLUMN dedup_key TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_board ON board_entries"
            "(case_id, run_id, agent_name, kind, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_board_dedup ON board_entries"
            "(case_id, run_id, agent_name, kind, dedup_key)"
        )


def add_entry(
    case_id: str,
    run_id: str,
    agent_name: str,
    kind: str,
    content: str,
    source: str = "",
    confidence: str = "high",
    status: str = "open",
    dedup_key: str | None = None,
) -> dict[str, Any]:
    # When a dedup_key is supplied, collapse on it (e.g. a fact stripped of its
    # volatile event id / timestamp). Otherwise fall back to exact-content match.
    norm = content.strip().lower()
    key = (dedup_key or "").strip().lower()
    with _lock, _conn() as conn:
        if key:
            existing = conn.execute(
                """SELECT id FROM board_entries
                   WHERE case_id=? AND run_id=? AND agent_name=? AND kind=?
                     AND dedup_key=?""",
                (case_id, run_id, agent_name, kind, key),
            ).fetchone()
        else:
            existing = conn.execute(
                """SELECT id FROM board_entries
                   WHERE case_id=? AND run_id=? AND agent_name=? AND kind=?
                     AND lower(trim(content))=?""",
                (case_id, run_id, agent_name, kind, norm),
            ).fetchone()
        if existing:
            row = conn.execute(
                "SELECT * FROM board_entries WHERE id=?", (existing["id"],)
            ).fetchone()
            return dict(row)
        entry_id = f"entry_{uuid.uuid4().hex[:12]}"
        now = _now()
        conn.execute(
            """INSERT INTO board_entries
               (id, case_id, run_id, agent_name, kind, content, source,
                confidence, status, created_at, updated_at, dedup_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (entry_id, case_id, run_id, agent_name, kind, content,
             source, confidence, status, now, now, key),
        )
    return get_entry(entry_id)


def get_entry(entry_id: str) -> dict[str, Any] | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM board_entries WHERE id=?", (entry_id,)
        ).fetchone()
    return dict(row) if row else None


def list_entries(
    case_id: str, run_id: str, agent_name: str
) -> list[dict[str, Any]]:
    init_db()
    with _conn() as conn:
        rows = conn.execute(
            """SELECT * FROM board_entries
               WHERE case_id=? AND run_id=? AND agent_name=?
               ORDER BY CASE kind
                   WHEN 'artifact' THEN 0
                   WHEN 'fact' THEN 1
                   WHEN 'hypothesis' THEN 2
                   ELSE 3
                 END, created_at ASC""",
            (case_id, run_id, agent_name),
        ).fetchall()
    return [dict(r) for r in rows]


def update_entry(entry_id: str, **fields) -> dict[str, Any] | None:
    allowed = {"content", "source", "confidence", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_entry(entry_id)
    updates["updated_at"] = _now()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [entry_id]
    with _lock, _conn() as conn:
        conn.execute(f"UPDATE board_entries SET {set_clause} WHERE id=?", values)
        row = conn.execute(
            "SELECT * FROM board_entries WHERE id=?", (entry_id,)
        ).fetchone()
    return dict(row) if row else None


def delete_entry(entry_id: str) -> bool:
    with _lock, _conn() as conn:
        cur = conn.execute("DELETE FROM board_entries WHERE id=?", (entry_id,))
        return cur.rowcount > 0
