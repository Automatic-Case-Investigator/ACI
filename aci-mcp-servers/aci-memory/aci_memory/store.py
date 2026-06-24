"""Read-only access layer over the ACI memory tables.

The memory layer (patterns, baselines, analyst feedback) is owned by Django: the
source of truth is the Django models in `agent/models.py`, curated through the
admin. This MCP server is a thin READ surface for agents, so it opens the same
SQLite database (`db.sqlite3`) directly in read-only mode and never writes.

Coupling note: the table/column names below mirror Django's auto-generated schema
for the `agent` app (`agent_<modelname>`). Writes (create/approve/expire) happen
exclusively through Django; this module only SELECTs.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

# Set by the provider to the Django default DB path.
_DB_PATH = os.environ.get("ACI_MEMORY_DB_PATH", "db.sqlite3")

T_PATTERN = "agent_patternentry"
T_BASELINE = "agent_baselinesnapshot"
T_FEEDBACK = "agent_feedbackentry"


def _connect() -> sqlite3.Connection:
    # Read-only URI connection so an agent run can never mutate curated memory.
    uri = f"file:{_DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _loads(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_expired(expires_at: Any) -> bool:
    if not expires_at:
        return True
    try:
        # Django stores aware datetimes as ISO strings (often with offset or 'Z').
        text = str(expires_at).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt > _now()
    except (ValueError, TypeError):
        return True


def _pattern_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "verdict": row["verdict"],
        "conditions": _loads(row["conditions"], {}),
        "required_evidence": _loads(row["required_evidence"], []),
        "invalidators": _loads(row["invalidators"], []),
        "confidence": row["confidence"],
        "owner": row["owner"],
        "expires_at": row["expires_at"],
        "enabled": bool(row["enabled"]),
    }


def search_patterns(
    verdict: str | None = None,
    rule_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return enabled, non-expired patterns.

    Optionally filtered to a verdict (`tp`/`fp`) and/or patterns whose
    `conditions.rule_ids` overlap the supplied `rule_ids`.
    """
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return []
    try:
        rows = conn.execute(
            f"SELECT * FROM {T_PATTERN} WHERE enabled=1 ORDER BY updated_at DESC"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    wanted_rules = {str(r) for r in (rule_ids or [])}
    out: list[dict[str, Any]] = []
    for row in rows:
        pat = _pattern_row(row)
        if not _not_expired(pat["expires_at"]):
            continue
        if verdict and pat["verdict"] != verdict:
            continue
        if wanted_rules:
            pat_rules = {str(r) for r in pat["conditions"].get("rule_ids", [])}
            if not (pat_rules & wanted_rules):
                continue
        out.append(pat)
    return out


def list_baseline_entities(subject_type: str | None = None) -> list[dict[str, Any]]:
    """Return distinct (subject_type, subject_id) pairs that have computed baselines."""
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return []
    try:
        if subject_type:
            rows = conn.execute(
                f"SELECT DISTINCT subject_type, subject_id FROM {T_BASELINE} "
                "WHERE subject_type=? ORDER BY subject_type, subject_id",
                (subject_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT DISTINCT subject_type, subject_id FROM {T_BASELINE} "
                "ORDER BY subject_type, subject_id"
            ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [{"subject_type": r["subject_type"], "subject_id": r["subject_id"]} for r in rows]


def get_baselines(subject_type: str, subject_id: str) -> list[dict[str, Any]]:
    """Return all baseline features for one subject (endpoint/user/service)."""
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return []
    try:
        rows = conn.execute(
            f"SELECT * FROM {T_BASELINE} WHERE subject_type=? AND subject_id=? "
            "ORDER BY feature ASC",
            (subject_type, subject_id),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [
        {
            "subject_type": r["subject_type"],
            "subject_id": r["subject_id"],
            "feature": r["feature"],
            "value": _loads(r["value"], {}),
            "window_days": r["window_days"],
            "health": r["health"],
            "computed_at": r["computed_at"],
        }
        for r in rows
    ]


def search_feedback(
    case_id: str | None = None,
    rule_ids: list[str] | None = None,
    days: int | None = 30,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return analyst feedback entries.

    When `case_id` is provided, returns all feedback for that case (no time
    limit, no row cap).

    When `case_id` is omitted, returns recent cross-case feedback ordered by
    most recently updated, capped by `days` and `limit`. Pass `rule_ids` to
    receive only entries whose stored context overlaps with those rule IDs —
    the overlap check is done in Python after fetching because SQLite has no
    JSON array intersection operator.
    """
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return []

    try:
        if case_id is not None:
            rows = conn.execute(
                f"SELECT * FROM {T_FEEDBACK} WHERE case_id=? ORDER BY updated_at DESC",
                (case_id,),
            ).fetchall()
        else:
            params: list[Any] = []
            where_clauses = []
            if days:
                where_clauses.append("updated_at >= datetime('now', ?)")
                params.append(f"-{int(days)} days")
            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            rows = conn.execute(
                f"SELECT * FROM {T_FEEDBACK} {where} ORDER BY updated_at DESC LIMIT ?",
                [*params, int(limit)],
            ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    wanted_rules = {str(r).strip() for r in (rule_ids or [])} if rule_ids else None

    out = []
    for r in rows:
        ctx = _loads(r["context"], {})
        if wanted_rules:
            entry_rules = {str(x).strip() for x in ctx.get("rule_ids", [])}
            if not (entry_rules & wanted_rules):
                continue
        out.append({
            "case_id": r["case_id"],
            "run_id": r["run_id"],
            "agent_name": r["agent_name"],
            "original_verdict": _loads(r["original_verdict"], None),
            "analyst_verdict": _loads(r["analyst_verdict"], None),
            "context": ctx,
            "note": r["note"],
            "created_by": r["created_by"],
            "updated_at": r["updated_at"],
        })
    return out
