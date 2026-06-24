"""SQLite-backed TI result cache, keyed by (provider, kind, value, case_id)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import TIResult

_lock = threading.Lock()

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS ti_cache (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    provider   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    case_id    TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    score      REAL,
    indicators TEXT NOT NULL DEFAULT '',
    reference  TEXT NOT NULL DEFAULT '',
    raw_json   TEXT NOT NULL DEFAULT '{}',
    cached_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ti_cache_key
    ON ti_cache (provider, kind, value, case_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TICache:
    def __init__(self, db_path: str, ttl_hours: int = 24) -> None:
        self._db_path = os.path.abspath(db_path)
        self._ttl = timedelta(hours=max(0, ttl_hours))
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
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

    def _init_db(self) -> None:
        with _lock, self._conn() as conn:
            conn.executescript(_CREATE_SQL)
        self.cleanup_expired()

    def get(
        self,
        provider: str,
        kind: str,
        value: str,
        case_id: str,
    ) -> Optional[TIResult]:
        now = _now_iso()
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM ti_cache
                   WHERE provider=? AND kind=? AND value=? AND case_id=?
                     AND expires_at > ?""",
                (provider, kind, value.lower(), case_id, now),
            ).fetchone()
        if row is None:
            return None
        return TIResult(
            provider=row["provider"],
            artifact_kind=row["kind"],
            artifact_value=row["value"],
            verdict=row["verdict"],
            score=row["score"],
            indicators=row["indicators"],
            reference=row["reference"],
            raw=json.loads(row["raw_json"] or "{}"),
        )

    def set(self, result: TIResult, case_id: str) -> None:
        now = datetime.now(timezone.utc)
        expires = (now + self._ttl).isoformat()
        with _lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ti_cache
                   (provider, kind, value, case_id,
                    verdict, score, indicators, reference, raw_json,
                    cached_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.provider,
                    result.artifact_kind,
                    result.artifact_value.lower(),
                    case_id,
                    result.verdict,
                    result.score,
                    result.indicators,
                    result.reference,
                    json.dumps(result.raw),
                    now.isoformat(),
                    expires,
                ),
            )
        self.cleanup_expired()

    def cleanup_expired(self) -> int:
        """Delete expired cache entries. Returns count deleted."""
        now = _now_iso()
        with _lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM ti_cache WHERE expires_at < ?", (now,))
            return cur.rowcount

    def stats(self) -> dict:
        """Return {"total": N, "by_provider": {"virustotal": N, ...}}."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM ti_cache").fetchone()[0]
            rows = conn.execute(
                "SELECT provider, COUNT(*) as cnt FROM ti_cache GROUP BY provider"
            ).fetchall()
        return {"total": total, "by_provider": {r["provider"]: r["cnt"] for r in rows}}

    def clear_all(self) -> int:
        """Delete all cache entries. Returns count deleted."""
        with _lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM ti_cache")
            return cur.rowcount
