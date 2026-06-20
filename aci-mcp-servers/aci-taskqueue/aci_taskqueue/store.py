"""SQLite-backed task store for per-agent queues.

All operations use the standard library sqlite3 module. The database is
created on first use at the path set by TASKQUEUE_DB_PATH.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

_lock = threading.Lock()
_DB_PATH = os.environ.get("TASKQUEUE_DB_PATH", "taskqueue.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


from contextlib import contextmanager

@contextmanager
def _conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # The DB is shared between this process and the agent's MCP subprocess; wait
    # rather than fail immediately when the other side holds a write lock.
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
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                priority INTEGER NOT NULL DEFAULT 50,
                status TEXT NOT NULL DEFAULT 'pending',
                origin TEXT NOT NULL DEFAULT 'agent',
                summary TEXT NOT NULL DEFAULT '',
                avfs_paths TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                claimed_at TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_queue ON tasks(case_id, run_id, agent_name, status, priority)")


def create_task(
    case_id: str,
    run_id: str,
    agent_name: str,
    title: str,
    description: str = "",
    priority: int = 50,
    origin: str = "agent",
) -> dict[str, Any]:
    task_id = f"task_{uuid.uuid4().hex[:12]}"
    now = _now()
    with _lock, _conn() as conn:
        conn.execute(
            """INSERT INTO tasks
               (id, case_id, run_id, agent_name, title, description,
                priority, status, origin, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,'pending',?,?,?)""",
            (task_id, case_id, run_id, agent_name, title, description, priority, origin, now, now),
        )
    return get_task(task_id)


def get_task(task_id: str) -> dict[str, Any] | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    return dict(row) if row else None


def list_tasks(case_id: str, run_id: str, agent_name: str) -> list[dict[str, Any]]:
    with _conn() as conn:
        rows = conn.execute(
            """SELECT * FROM tasks
               WHERE case_id=? AND run_id=? AND agent_name=?
               ORDER BY priority DESC, created_at ASC""",
            (case_id, run_id, agent_name),
        ).fetchall()
    return [dict(r) for r in rows]


def claim_next(case_id: str, run_id: str, agent_name: str) -> dict[str, Any] | None:
    """Atomically claim the highest-priority pending task."""
    with _lock, _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT id FROM tasks
               WHERE case_id=? AND run_id=? AND agent_name=? AND status='pending'
               ORDER BY priority DESC, created_at ASC LIMIT 1""",
            (case_id, run_id, agent_name),
        ).fetchone()
        if row is None:
            return None
        task_id = row["id"]
        now = _now()
        conn.execute(
            "UPDATE tasks SET status='claimed', claimed_at=?, updated_at=? WHERE id=?",
            (now, now, task_id),
        )
        updated = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    return dict(updated) if updated else None


def update_task(task_id: str, **fields) -> dict[str, Any] | None:
    allowed = {"title", "description", "priority", "status", "summary", "avfs_paths"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_task(task_id)
    updates["updated_at"] = _now()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [task_id]
    with _lock, _conn() as conn:
        conn.execute(f"UPDATE tasks SET {set_clause} WHERE id=?", values)
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    return dict(row) if row else None


def complete_task(task_id: str, summary: str, avfs_paths: list[str] | None = None) -> dict[str, Any] | None:
    summary = (summary or "").strip()
    if not summary:
        raise ValueError("A non-empty completion summary is required")
    return update_task(
        task_id,
        status="completed",
        summary=summary,
        avfs_paths=json.dumps(avfs_paths or []),
    )


def fail_task(task_id: str, reason: str) -> dict[str, Any] | None:
    return update_task(task_id, status="failed", summary=reason)


def dismiss_task(task_id: str, reason: str = "") -> dict[str, Any] | None:
    return update_task(task_id, status="dismissed", summary=reason)


def reopen_task(task_id: str) -> dict[str, Any] | None:
    return update_task(task_id, status="pending")


def delete_task(task_id: str) -> bool:
    """Hard-delete a task. Returns True if a row was removed."""
    with _lock, _conn() as conn:
        cur = conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        return cur.rowcount > 0


def reorder(case_id: str, run_id: str, agent_name: str, ordered_ids: list[str]) -> list[dict[str, Any]]:
    """Rewrite task priorities so the queue follows `ordered_ids`.

    `claim_next`/`list_tasks` order by priority DESC then created_at ASC, so to impose an
    explicit order we assign descending priorities to the ids in `ordered_ids` (first = highest).
    Ids not present in `ordered_ids` keep their current priority and sort after.
    """
    now = _now()
    n = len(ordered_ids)
    with _lock, _conn() as conn:
        for idx, task_id in enumerate(ordered_ids):
            # Space priorities out (top of list gets the highest value).
            priority = (n - idx) * 10
            conn.execute(
                "UPDATE tasks SET priority=?, updated_at=? WHERE id=? AND case_id=? AND run_id=? AND agent_name=?",
                (priority, now, task_id, case_id, run_id, agent_name),
            )
    return list_tasks(case_id, run_id, agent_name)
