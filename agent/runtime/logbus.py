"""Structured agent log events.

A single `emit()` call produces one `LogEvent` that fans out to every handler on
the "agent" logger tree:

- the CLI's live pane renders the concise one-line `summary`;
- the run-log file writes the full, untruncated `detail`.

This is how "concise on screen, complete on disk" is achieved without redacting
anything: the screen shows `summary`, the file keeps `detail`.

Agent code should prefer `emit(...)` over `logging.info(...)` for anything an
analyst should see. Plain `logging` calls on the "agent" tree still work — the
CLI handler synthesizes a low-key event for them so nothing is lost.
"""
from __future__ import annotations

import contextvars
import itertools
import json
import logging
import threading
from dataclasses import dataclass
from time import time
from typing import Any, Optional

_events_log = logging.getLogger("agent.events")
_seq = itertools.count(1)

# Dashboard correlation. `session` groups every event of one analyst question
# (= the orchestrator AgentRun id); `run` is the specific AgentRun currently
# executing. Both are set once at a run's entrypoint and inherited by the asyncio
# task context, so nested emits (orchestrator -> triage -> investigation) carry them.
_session: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("aci_session", default=None)
_run: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("aci_run", default=None)
_ctx_lock = threading.Lock()
_ctx_by_run: dict[str, dict] = {}
_issue_lock = threading.Lock()
_issues_by_run: dict[str, list[dict]] = {}


def bind_session(session_id: str):
    return _session.set(session_id)


def reset_session(token) -> None:
    _session.reset(token)


def bind_run(run_id: str):
    return _run.set(run_id)


def reset_run(token) -> None:
    _run.reset(token)


def current_session() -> Optional[str]:
    return _session.get()


def current_run() -> Optional[str]:
    return _run.get()


def update_context_usage(tokens: int, source: str) -> None:
    """Record latest model input-token usage for the current agent run."""
    session_id = _session.get()
    run_id = _run.get() or session_id
    if not session_id or not run_id or not tokens:
        return
    with _ctx_lock:
        _ctx_by_run[run_id] = {
            "session_id": session_id,
            "run_id": run_id,
            "source": source,
            "tokens": tokens,
            "ts": time(),
        }


def get_context_usage(run_id: str) -> dict | None:
    with _ctx_lock:
        item = _ctx_by_run.get(run_id)
        return dict(item) if item else None


def get_latest_context_usage(session_id: str) -> dict | None:
    with _ctx_lock:
        items = [v for v in _ctx_by_run.values() if v.get("session_id") == session_id]
        if not items:
            return None
        return dict(max(items, key=lambda v: v.get("ts", 0)))


def clear_run_issues(run_id: str) -> None:
    with _issue_lock:
        _issues_by_run.pop(str(run_id), None)


def get_run_issues(run_id: str) -> list[dict]:
    with _issue_lock:
        return [dict(item) for item in _issues_by_run.get(str(run_id), [])]


def _record_issue(ev: "LogEvent") -> None:
    if ev.kind not in {"error", "warning", "warn"} or not ev.run_id:
        return
    with _issue_lock:
        _issues_by_run.setdefault(str(ev.run_id), []).append({
            "source": ev.source,
            "kind": ev.kind,
            "summary": ev.summary,
            "detail": ev.detail or "",
        })


def next_seq() -> int:
    """Monotonic, process-wide event sequence number (stable for `show <n>`)."""
    return next(_seq)


@dataclass
class LogEvent:
    seq: int
    ts: float
    source: str           # "orch" | "tri" | "inv" | "cli" | "log"
    kind: str             # think|stream|intent_delta|intent|call|result|task|note|error|route|answer|done|finding
    summary: str          # one line, already trimmed for display
    detail: Optional[str] = None   # full untruncated payload (may be large/multiline)
    expand: bool = False  # render detail inline automatically (answers, findings)
    session_id: Optional[str] = None  # dashboard grouping (filled from contextvar)
    run_id: Optional[str] = None      # specific AgentRun (filled from contextvar)
    metadata: dict[str, Any] | None = None


def emit(
    source: str,
    kind: str,
    summary: str,
    detail: str | None = None,
    *,
    expand: bool = False,
    metadata: dict[str, Any] | None = None,
) -> LogEvent:
    ev = LogEvent(
        next_seq(), time(), source, kind, summary, detail, expand,
        session_id=_session.get(), run_id=_run.get(), metadata=metadata or {},
    )
    _record_issue(ev)
    _events_log.info(summary, extra={"logevent": ev})
    return ev


# ── source labels ──────────────────────────────────────────────────────────────
_SRC = {"investigation": "inv", "triage": "tri", "orchestrator": "orch"}


def src_label(agent_name: str) -> str:
    return _SRC.get(agent_name, (agent_name or "?")[:4])


# ── summarizers (build the one-line `summary` from raw payloads) ─────────────────
def _clip(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def summarize_think(text: str) -> str:
    return _clip(text, 140)


def summarize_stream(text: str) -> str:
    return _clip(text, 80)


def summarize_intent(text: str) -> str:
    return _clip(text, 180)


def summarize_args(args: dict) -> str:
    try:
        s = json.dumps(args, default=str, separators=(",", ":"))
    except Exception:
        s = str(args)
    return _clip(s, 100)


def summarize_result(tool: str, content: str) -> str:
    """Condense a tool result to one scannable line. Best-effort; never raises."""
    c = (content or "").strip()
    try:
        obj = json.loads(c)
    except Exception:
        obj = None

    if isinstance(obj, dict):
        if "error" in obj and len(obj) <= 2:
            return f"ERROR {_clip(str(obj['error']), 120)}"
        if "total" in obj or "events" in obj:
            events = obj.get("events") or []
            n = obj.get("total") if obj.get("total") is not None else len(events)
            first = ""
            if events and isinstance(events[0], dict):
                fid = events[0].get("_id") or events[0].get("id")
                if fid:
                    first = f" first={fid}"
            return f"{n} hit(s){first}"
        if "top_values" in obj:
            tv = obj.get("top_values") or []
            head = ", ".join(f"{b.get('value')}({b.get('count')})" for b in tv[:3])
            return f"{obj.get('field', '?')}: {head}" + (" …" if len(tv) > 3 else "")
        if "tasks" in obj:
            return f"{len(obj['tasks'])} task(s)"
        if "indices" in obj:
            return f"{len(obj['indices'])} index(es)"
        if "fields" in obj:
            return f"{len(obj['fields'])} field(s)"
        if "_id" in obj:  # a single fetched document
            return f"doc {obj['_id']}"
        return _clip("{" + ", ".join(list(obj.keys())[:5]) + "}", 80)

    if isinstance(obj, list):
        return f"{len(obj)} item(s)"

    first_line = c.splitlines()[0] if c else "(empty)"
    return _clip(first_line, 120)
