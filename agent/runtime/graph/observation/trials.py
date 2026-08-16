from __future__ import annotations

"""Query-trial records: what shape was tried, in what window, to what outcome."""

from ..timeutil import _find_timestamp_range
from ..timeutil import _format_dt
from ..timeutil import _parse_dt
import json
from ...analysis.query_memo import normalize_query_shape
import re


_SEARCH_TOOLS = frozenset({"search", "search_keyword"})


_EVENT_SNAPSHOT_TOOLS = frozenset({"search", "search_keyword", "get_event"})


_PROFILE_TOOLS = frozenset({"get_event_volume", "profile_field"})


_EVIDENCE_TOOLS = frozenset(
    {
        "search",
        "search_keyword",
        "profile_field",
        "get_event_volume",
        "correlate_entity",
        "correlate_techniques",
        "get_event",
    }
)


_STRONG_SIGNALS = frozenset({"TRUNCATED", "SATURATED", "FLOODED", "ORIENTATION_ONLY"})


_CASE_URL_EXEMPLAR_RULE_IDS = frozenset({"31151"})


_INVALID_TIME_RE = re.compile(
    r"Invalid SIEM time range:\s*([0-9T:.\-+Z]+)\s+to\s+([0-9T:.\-+Z]+)\.",
    re.IGNORECASE,
)


_TASK_WINDOW_RE = re.compile(
    r"The claimed task specifies\s*([0-9T:.\-+Z]+)\s+to\s+([0-9T:.\-+Z]+)\.",
    re.IGNORECASE,
)


_TIME_WINDOW_TOOLS = frozenset(
    {
        "search",
        "search_keyword",
        "profile_field",
        "get_event_volume",
        "correlate_entity",
        "correlate_techniques",
    }
)


_QUERY_FOCUS_TOOLS = frozenset({"search", "search_keyword", "profile_field"})


_EVENT_CONTAINER_KEYS = (
    "events",
    "hits",
    "results",
    "documents",
    "alerts",
    "minority_sample",
)


_EVENT_ID_KEYS = ("_id", "event.id", "event_id")


def _load(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None
    return None


def _tool_time_window(tool_name: str, args: dict) -> dict | None:
    if tool_name not in _TIME_WINDOW_TOOLS or not isinstance(args, dict):
        return None
    if tool_name in {"get_event_volume", "correlate_entity", "correlate_techniques"}:
        start, end = args.get("start_time"), args.get("end_time")
    else:
        tr = args.get("time_range") if isinstance(args.get("time_range"), dict) else {}
        start, end = tr.get("from"), tr.get("to")
        if not (start and end):
            start, end = _find_timestamp_range(args.get("query"))
    start_dt, end_dt = _parse_dt(start), _parse_dt(end)
    if not (start_dt and end_dt and end_dt > start_dt):
        return None
    return {"tool": tool_name, "from": _format_dt(start_dt), "to": _format_dt(end_dt)}


def _tool_query_focus(tool_name: str, args: dict) -> dict | None:
    if tool_name not in _QUERY_FOCUS_TOOLS or not isinstance(args, dict):
        return None
    shape = normalize_query_shape(tool_name, args)
    if tool_name == "profile_field":
        field = " ".join(str(args.get("field") or "").split())
        if not field:
            return None
        shape = f"profile:{field.lower()}"
    if not shape:
        return None
    return {"tool": tool_name, "focus": shape[:500]}


def _trial_outcome(
    tool_signals: list[str], hits, *, is_error: bool, has_events: bool
) -> str:
    """One-word outcome class for a query trial, from the signals already derived.
    Ordered so the most decisive class wins (a flood is a flood even if truncated)."""
    if is_error:
        return "error"
    s = set(tool_signals or [])
    if "FLOODED" in s:
        return "flood"
    if "TRUNCATED" in s:
        return "truncated"
    if "EMPTY" in s:
        return "empty"
    if has_events or (isinstance(hits, int) and hits > 0):
        return "scoped_hits"
    return "aggregate"


def _trial_record(
    focus: dict | None,
    window: dict | None,
    outcome: str,
    hits,
    evidence: list[str] | None = None,
) -> dict | None:
    """A single (discriminator, window, outcome) trial the agent can reason over across
    cycles. Reuses the existing focus (value-bearing query shape) and window extractors,
    so a repeated dead shape like `url=/wp-content/create_account` is captured verbatim.
    `evidence` is a compact digest of the events this trial actually retrieved (rule / url /
    status / command / user), so the interpreter can analyze WHAT each past query returned —
    not just its hit count — after those events scroll out of the current observation.
    None when the run carried neither a discriminator nor a window (e.g. an orientation
    tool or a bare get_event by id — not a matching-logic trial)."""
    disc = (focus or {}).get("focus") or ""
    win = f"{window['from']}..{window['to']}" if window else ""
    if not disc and not win:
        return None
    record = {"discriminator": disc, "window": win, "outcome": outcome}
    if isinstance(hits, int):
        record["hits"] = hits
    sample = [line for line in (evidence or []) if line][:3]
    if sample:
        record["evidence"] = sample
    return record
