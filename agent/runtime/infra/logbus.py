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
_debug: contextvars.ContextVar[bool] = contextvars.ContextVar("aci_debug_mode", default=False)
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


def bind_debug_mode(enabled: bool):
    return _debug.set(bool(enabled))


def reset_debug_mode(token) -> None:
    _debug.reset(token)


def debug_mode_enabled() -> bool:
    return _debug.get()


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
    return text or ""


def summarize_args(args: dict) -> str:
    try:
        s = json.dumps(args, default=str, separators=(",", ":"))
    except Exception:
        s = str(args)
    return _clip(s, 100)


def _hhmm(ts) -> str:
    """HH:MM from an ISO bucket key, else the raw value."""
    s = str(ts or "")
    return s[11:16] if len(s) >= 16 and s[10] in ("T", " ") else s


def _stamp(ts) -> str:
    """MM-DD HH:MM from an ISO bucket key — keeps the date so a multi-day span is not
    rendered as a misleading same-looking HH:MM (e.g. '12:00->12:00' across two days)."""
    s = str(ts or "")
    return f"{s[5:10]} {s[11:16]}" if len(s) >= 16 and s[10] in ("T", " ") else s


def _summarize_volume(obj: dict) -> str:
    """One-line shape of a get_event_volume histogram: a saturation warning when the
    active region fills the window, the active regime (onset→cessation) for a sustained
    plateau, else peak + post-peak tail."""
    total = obj.get("total", 0)
    interval = obj.get("interval", "?")
    peak = obj.get("peak_bucket") or {}
    post = obj.get("post_spike_active_bins") or []
    head = f"volume: {total} ev / {interval}"
    onset, cessation = obj.get("onset") or {}, obj.get("cessation") or {}
    active = obj.get("active_bins") or []
    # Multiple distinct bursts: surface them so the agent picks the right sub-window
    # instead of treating the whole span as one event.
    bursts = obj.get("bursts") or []
    if len(bursts) > 1:
        shown = ", ".join(f"{_stamp(b.get('start'))}->{_stamp(b.get('end'))}({b.get('total')})"
                          for b in bursts[:4])
        more = f" +{len(bursts) - 4}" if len(bursts) > 4 else ""
        return f"{head}; {len(bursts)} BURSTS: {shown}{more} - pick the one matching your objective"
    # Saturated: activity fills the window — the profile localized nothing. Show dated
    # stamps and tell the agent to narrow, not to "query the edges".
    if obj.get("saturated") and onset and cessation:
        return (
            f"{head}; ACTIVE {_stamp(onset.get('time'))}->{_stamp(cessation.get('time'))} "
            f"SPANS WHOLE WINDOW - too broad; SHRINK the time window (not the interval), don't conclude"
        )
    # Sustained activity: a multi-bin block bounded by onset/cessation. Surfacing the
    # edges beats surfacing the peak — the plateau's start/end are the windows to drill.
    if onset and cessation and len(active) > 2:
        return (
            f"{head}; ACTIVE {_hhmm(onset.get('time'))}->{_hhmm(cessation.get('time'))} "
            f"({len(active)} bins) - plateau, query onset+cessation edges, don't conclude from shape"
        )
    if peak:
        head += f"; peak {_hhmm(peak.get('time'))}({peak.get('count')})"
    if post:
        shown = ", ".join(_hhmm(b.get("time")) for b in post[:6])
        more = f" +{len(post) - 6}" if len(post) > 6 else ""
        head += f"; POST-PEAK at {shown}{more} - step past the spike, query these"
    elif peak:
        head += "; no activity after peak"
    return head


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
        # get_event_volume: surface the temporal SHAPE (peak + post-peak tail), not just
        # the total — the tail is where post-spike activity lives.
        if "bins" in obj and isinstance(obj.get("bins"), list):
            return _summarize_volume(obj)
        if "total" in obj or "events" in obj:
            events = obj.get("events") or []
            n_total = obj.get("total") if obj.get("total") is not None else len(events)
            # With track_total_hits=False, total.value can be 0 even when events
            # are returned (OpenSearch short-circuits counting).  Use the larger
            # of the reported total and the actual event list length so the
            # summary never shows "0 hit(s) first=X".
            n = max(n_total, len(events))
            first = ""
            if events and isinstance(events[0], dict):
                fid = events[0].get("_id") or events[0].get("id")
                if fid:
                    first = f" first={fid}"
            # For an over-broad result, name the dominant behaviour class so the flood's
            # composition is visible at a glance (scope to a class to escape it).
            classes = obj.get("rule_groups_breakdown") or []
            top_class = f" top-class:{classes[0].get('group')}({classes[0].get('count')})" if classes else ""
            # When a flood has a discriminating axis, name it (and whether needle events
            # were returned) so the agent sees the residue move at a glance.
            disc = ""
            smap = obj.get("selectivity_map") or []
            d = next((e for e in smap if e.get("role") == "discriminator"), None)
            if d and d.get("minorities"):
                nsamp = len(obj.get("minority_sample") or [])
                # Show the RAREST minority (the needle candidate), not the largest.
                rarest = d["minorities"][-1].get("value")
                disc = (f" discriminator:{d['field']} (dom {d.get('dominant')} "
                        f"{round(d.get('dominant_share', 0) * 100)}%; needle~{rarest}; sample={nsamp})")
            # When the count is a capped lower bound (total.relation="gte"), the returned
            # events are an arbitrary slice of a much larger set — say so loudly so the
            # agent narrows instead of trusting a sample that hides the key events.
            if obj.get("truncated") or obj.get("total_relation") == "gte":
                return f">={n} hits (TRUNCATED - narrow / scope by rule.groups){top_class}{disc}{first}"
            # search_keyword flags: an OR-fallback (no all-term match → whole-host dump)
            # or an all-term match that is still huge. Both mean "do not trust this".
            if obj.get("broadened"):
                return f"{n} hits (OR-FALLBACK: no all-term match; refine terms){first}"
            if obj.get("too_broad"):
                return f"{n} hits (TOO BROAD: add a discriminator / narrow window){first}"
            return f"{n} hit(s){disc}{first}"
        if "rare_values" in obj:
            rv = obj.get("rare_values") or []
            head = ", ".join(f"{b.get('value')}({b.get('count')})" for b in rv[:4])
            return (f"{obj.get('field', '?')} RARE: {head}" + (" …" if len(rv) > 4 else "")
                    if rv else f"{obj.get('field', '?')} RARE: (none ≤{obj.get('max_doc_count')})")
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
