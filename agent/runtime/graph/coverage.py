from __future__ import annotations

"""Deterministic coverage-gap detectors over a task's message history.

These measure what the agent PROFILED but never QUERIED — the shape of a task that
mapped a window and then dwelt in one slice of it. They are pure functions over the
message list so every stage can read them: `interpret` (which owns the completion
decision), `think` (the evidence floor), and the finalize node (which feeds them to
the findings review).

Lives outside `nodes_flow/` because `nodes_flow` imports `nodes_loop`, so anything
both sides need has to sit below them or the import graph cycles.
"""

import json
import re
from datetime import datetime, timedelta

from .timeutil import _find_timestamp_range
from .toolio import _is_error_tool_result

# Tools that constitute genuine SIEM EVIDENCE retrieval, as opposed to orientation
# (get_case, list_tasks, get_board, search_patterns, ls/cat). The evidence floor and
# the depth signals both key on this boundary.
_EVIDENCE_TOOLS = frozenset({
    "search", "search_keyword", "profile_field", "get_event_volume",
    "correlate_entity", "correlate_techniques", "get_event",
})
# Search tools whose result hit count signals query specificity.
_SEARCH_RESULT_TOOLS = frozenset({"search", "search_keyword"})
# Minimum unqueried span worth reporting as a coverage gap.
_MIN_COVERAGE_GAP = timedelta(minutes=10)
# How far past a burst's cessation still counts as "should have been queried" — the
# low-volume follow-on tail, in bin widths.
_POST_CESSATION_TAIL_BINS = 2


def _count_evidence_queries(messages: list) -> int:
    """Count non-error SIEM evidence-retrieval results in a task's message history.

    Orientation calls are excluded, so a task padded with bookkeeping is not credited
    as deep investigation. Accurate only because the history is retained across cycles
    — it used to see one cycle at a time and under-report.
    """
    n = 0
    for msg in messages:
        if getattr(msg, "name", "") in _EVIDENCE_TOOLS:
            if not _is_error_tool_result(getattr(msg, "content", "") or ""):
                n += 1
    return n


def _last_search_hit_count(messages: list) -> int | None:
    """Hit count of the most recent search/search_keyword tool result, or None.

    Feeds the per-task self-review as a deterministic signal: whether the task's latest
    evidence query was still at the unusable-result ceiling (i.e. never narrowed).
    """
    from ..analysis.query_memo import extract_hit_count

    for msg in reversed(messages):
        if getattr(msg, "name", "") in _SEARCH_RESULT_TOOLS:
            return extract_hit_count(getattr(msg, "content", "") or "")
    return None


def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _query_time_window(args: dict) -> tuple:
    """The (from, to) datetimes a search/search_keyword call targeted — from its
    `time_range` param or an embedded `@timestamp` range filter."""
    tr = args.get("time_range") or {}
    frm, to = tr.get("from"), tr.get("to")
    if not (frm and to):
        embedded = _find_timestamp_range(args.get("query"))
        if embedded:
            frm, to = embedded
    return _parse_iso(frm), _parse_iso(to)


def _unqueried_post_peak_clusters(messages: list) -> list[str]:
    """Post-peak activity clusters a `get_event_volume` surfaced but no raw
    `search`/`search_keyword` later drilled.

    A volume profile is a to-do list of windows, not a conclusion: each active bin
    flanking the spike (`pre_spike_active_bins` / `post_spike_active_bins`) is a time
    window still holding unexamined evidence (lateral movement, persistence execution,
    privesc, cleanup hide across the multi-hour active block, not just the minute after
    the peak). This returns the cluster timestamps that remain unqueried so the task
    review can keep the agent working until it drills them.
    """
    clusters: list[datetime] = []
    for m in messages:
        if getattr(m, "name", "") != "get_event_volume":
            continue
        try:
            data = json.loads(getattr(m, "content", "") or "")
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        flanking = (data.get("pre_spike_active_bins") or []) + (data.get("post_spike_active_bins") or [])
        for b in flanking:
            t = _parse_iso(b.get("time") if isinstance(b, dict) else None)
            if t:
                clusters.append(t)
    if not clusters:
        return []

    windows: list[tuple] = []
    for m in messages:
        for tc in getattr(m, "tool_calls", None) or []:
            if tc.get("name") not in _SEARCH_RESULT_TOOLS:
                continue
            frm, to = _query_time_window(tc.get("args") or {})
            if frm and to:
                windows.append((frm, to))

    out, seen = [], set()
    for c in clusters:
        if any(f <= c <= t for f, t in windows):
            continue
        key = c.strftime("%Y-%m-%dT%H:%M:%SZ")
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out[:8]


def _interval_seconds(interval: str) -> int | None:
    """Parse an OpenSearch fixed_interval string ('5m', '1h', '3600s') to seconds."""
    m = re.match(r"^\s*(\d+)\s*([smhd])\s*$", (interval or "").lower())
    if not m:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _merge_intervals(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    """Union overlapping/adjacent (start, end) intervals into a minimal sorted list."""
    merged: list[tuple[datetime, datetime]] = []
    for f, t in sorted(intervals):
        if merged and f <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], t))
        else:
            merged.append((f, t))
    return merged


def _unqueried_time_ranges(messages: list) -> list[str]:
    """Contiguous sub-ranges of the window the agent PROFILED with `get_event_volume`
    that no raw `search`/`search_keyword` ever covered.

    Complements `_unqueried_post_peak_clusters` (which flags discrete post-spike bins):
    this catches an investigation that DWELLS in one slice of a window it has already
    mapped as larger — the observed failure where every query clusters in the initial
    scan minutes and never advances to the hours the profile showed were active. The
    reference span is the active regime [onset, cessation] when the profile found one
    (else the full profiled bin envelope); the covered spans are the raw-search
    windows. Deterministic measurement — the reviewer decides whether an unexamined
    range is relevant to the task. The reference is extended a couple of bins PAST
    cessation so a low-volume follow-on (a payload/success just after a loud burst,
    below the histogram threshold) is flagged as an unqueried tail rather than lost.
    """
    refs: list[tuple[datetime, datetime]] = []
    for m in messages:
        if getattr(m, "name", "") != "get_event_volume":
            continue
        try:
            data = json.loads(getattr(m, "content", "") or "")
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        start = _parse_iso((data.get("onset") or {}).get("time"))
        end = _parse_iso((data.get("cessation") or {}).get("time"))
        had_regime = bool(start and end)
        if not had_regime:
            times = [
                _parse_iso(b.get("time"))
                for b in (data.get("bins") or [])
                if isinstance(b, dict)
            ]
            times = [t for t in times if t]
            if times:
                start, end = min(times), max(times)
        # Extend the reference past cessation to include the low-volume follow-on tail —
        # the payload/success often sits just past a loud burst, below the histogram's
        # active threshold, so it never shows as "active" and gets left unqueried. Skip
        # for a saturated profile (its cessation is already the window edge).
        if had_regime and end and not data.get("saturated"):
            isecs = _interval_seconds(data.get("interval") or "")
            if isecs:
                end = end + timedelta(seconds=_POST_CESSATION_TAIL_BINS * isecs)
        if start and end and end > start:
            refs.append((start, end))
    if not refs:
        return []

    covered: list[tuple[datetime, datetime]] = []
    for m in messages:
        for tc in getattr(m, "tool_calls", None) or []:
            if tc.get("name") not in _SEARCH_RESULT_TOOLS:
                continue
            frm, to = _query_time_window(tc.get("args") or {})
            if frm and to:
                covered.append((frm, to))
    merged_cov = _merge_intervals(covered)

    gaps: list[tuple[datetime, datetime]] = []
    for rs, re_ in _merge_intervals(refs):
        cursor = rs
        for cf, ct in merged_cov:
            if ct <= cursor or cf >= re_:
                continue
            if cf > cursor:
                gaps.append((cursor, min(cf, re_)))
            cursor = max(cursor, ct)
            if cursor >= re_:
                break
        if cursor < re_:
            gaps.append((cursor, re_))

    out = [
        f"{f.strftime('%Y-%m-%dT%H:%M:%SZ')}–{t.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        for f, t in gaps
        if t - f >= _MIN_COVERAGE_GAP
    ]
    return out[:6]
