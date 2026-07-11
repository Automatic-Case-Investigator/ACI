"""Deterministic normalization of tool-result batches into observation state."""
from __future__ import annotations

import json
import re

from ..analysis.query_memo import BROAD_HIT_THRESHOLD, extract_hit_count, normalize_query_shape
from .parsing import _PIVOT_CONF_SCORE, _PIVOT_ROLE_SCORE, _PIVOT_SOURCE_SCORE
from .timeutil import _find_timestamp_range, _format_dt, _parse_dt, _pivot_key

_SEARCH_TOOLS = frozenset({"search", "search_keyword"})
_EVENT_SNAPSHOT_TOOLS = frozenset({"search", "search_keyword", "get_event"})
_PROFILE_TOOLS = frozenset({"get_event_volume", "profile_field"})
_EVIDENCE_TOOLS = frozenset({
    "search", "search_keyword", "profile_field", "get_event_volume",
    "correlate_entity", "correlate_techniques", "get_event",
})
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
_TIME_WINDOW_TOOLS = frozenset({
    "search", "search_keyword", "profile_field", "get_event_volume",
    "correlate_entity", "correlate_techniques",
})
_QUERY_FOCUS_TOOLS = frozenset({"search", "search_keyword", "profile_field"})
_EVENT_CONTAINER_KEYS = ("events", "hits", "results", "documents", "alerts", "minority_sample")
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


def _trial_outcome(tool_signals: list[str], hits, *, is_error: bool, has_events: bool) -> str:
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
    focus: dict | None, window: dict | None, outcome: str, hits,
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


# ── Event extraction: pull event dicts / ids / fields out of tool-result JSON ──
def _flatten(value, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(child, path)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child, prefix)
    else:
        yield prefix.lower(), value


def _source_id(event: dict) -> str:
    flattened = dict(_flatten(event))
    for key in _EVENT_ID_KEYS:
        value = flattened.get(key)
        if value not in (None, ""):
            return str(value)
        for path, nested_value in flattened.items():
            if path.endswith(f".{key}") and nested_value not in (None, ""):
                return str(nested_value)
    return ""


def _event_dicts(obj) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()

    def add(event: dict) -> None:
        source = _source_id(event)
        if source:
            key = f"id:{source}"
        else:
            try:
                key = "raw:" + json.dumps(event, sort_keys=True, default=str)
            except TypeError:
                key = f"obj:{id(event)}"
        if key in seen:
            return
        seen.add(key)
        out.append(event)

    def add_items(items) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    add(item)

    def walk(value) -> None:
        if isinstance(value, list):
            add_items(value)
            return
        if not isinstance(value, dict):
            return

        found_container = False
        for key in _EVENT_CONTAINER_KEYS:
            items = value.get(key)
            if isinstance(items, list):
                found_container = True
                add_items(items)
            elif key == "hits" and isinstance(items, dict):
                nested_hits = items.get("hits")
                if isinstance(nested_hits, list):
                    found_container = True
                    add_items(nested_hits)

        data = value.get("data")
        if isinstance(data, (dict, list)):
            walk(data)

        if not found_container and _source_id(value):
            add(value)

    walk(obj)
    return out


def _event_fields(event: dict) -> dict:
    flattened = dict(_flatten(event))
    source = event.get("_source") if isinstance(event, dict) else None
    if isinstance(source, dict):
        for key, value in _flatten(source):
            flattened.setdefault(key, value)
    return flattened


def _event_ids(obj) -> list[str]:
    out: list[str] = []
    for event in _event_dicts(obj):
        value = _source_id(event)
        if value:
            out.append(str(value))
    return out[:8]


def _first_present(event: dict, names: tuple[str, ...]) -> str:
    for name in names:
        value = event.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _clip(value: object, limit: int = 320) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


# ── Evidence snapshots, digests, and orientation/volume facts ──
def _evidence_snapshots(tool_name: str, obj) -> list[dict]:
    """Extract compact, non-semantic event fields for model-side assimilation.

    This intentionally avoids judging whether a URL, command, or rule is malicious.
    Code only preserves the evidence-bearing fields that the interpreter needs in
    order to reason semantically without carrying full raw tool blobs forward.
    """
    if tool_name not in _EVENT_SNAPSHOT_TOOLS or not isinstance(obj, dict):
        return []
    events = _event_dicts(obj)

    out: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        fields = _event_fields(event)
        snapshot = {
            "event_id": _source_id(event),
            "timestamp": _first_present(fields, ("timestamp", "@timestamp", "data.timestamp")),
            "agent": _first_present(fields, ("agent.name", "agent", "host.name")),
            "rule_id": _first_present(fields, ("rule.id", "rule_id")),
            "rule_description": _first_present(fields, ("rule.description", "rule_desc", "description")),
            "rule_groups": _first_present(fields, ("rule.groups",)),
            "rule_level": _first_present(fields, ("rule.level",)),
            "src_ip": _first_present(fields, ("data.srcip", "src_ip", "source.ip", "srcip")),
            "dst_ip": _first_present(fields, ("data.dstip", "dst_ip", "destination.ip", "dstip")),
            "status": _first_present(fields, ("data.id", "http.response.status_code")),
            "url": _first_present(fields, ("data.url", "url", "http.url", "request")),
            "user_agent": _first_present(fields, ("data.user_agent", "http.user_agent", "user_agent")),
            "user": _first_present(fields, ("data.srcuser", "data.dstuser", "user.name", "user")),
            "command": _first_present(fields, (
                "data.command", "data.audit.command", "process.command_line",
                "data.audit.exe", "process.executable",
            )),
            "full_log": _clip(_first_present(fields, ("full_log", "message", "log", "raw")), 420),
        }
        compact = {key: value for key, value in snapshot.items() if value}
        if compact:
            out.append(compact)
        if len(out) >= 8:
            break
    return out


def _digest_line(snapshot: dict) -> str:
    """One compact, human-readable line for a single event snapshot — the semantic
    fields an analyst reads first, in a fixed order. Empty fields are skipped so the
    line stays dense. This is pure formatting of the already-extracted snapshot; it
    carries no judgement about maliciousness."""
    parts: list[str] = []
    rule = " ".join(p for p in (
        snapshot.get("rule_id") and f"rule {snapshot['rule_id']}",
        snapshot.get("rule_description"),
    ) if p)
    if rule:
        parts.append(rule)
    if snapshot.get("rule_groups"):
        parts.append(f"[{snapshot['rule_groups']}]")
    if snapshot.get("url"):
        url = snapshot["url"]
        parts.append(f"{url} →{snapshot['status']}" if snapshot.get("status") else url)
    elif snapshot.get("status"):
        parts.append(f"status {snapshot['status']}")
    if snapshot.get("command"):
        parts.append(f"cmd={snapshot['command']}")
    if snapshot.get("user"):
        parts.append(f"user={snapshot['user']}")
    if snapshot.get("src_ip") or snapshot.get("dst_ip"):
        flow = "→".join(p for p in (snapshot.get("src_ip"), snapshot.get("dst_ip")) if p)
        parts.append(flow)
    if snapshot.get("full_log") and not snapshot.get("command") and not snapshot.get("url"):
        parts.append(_clip(snapshot["full_log"], 160))
    return " | ".join(parts)


def _evidence_digest(snapshots: list[dict]) -> list[str]:
    """A short human-readable digest of the notable events in this batch, so the
    interpreter attends to WHAT was retrieved (paths, commands, statuses, users)
    rather than only how many hits came back."""
    out: list[str] = []
    seen: set[str] = set()
    for snapshot in snapshots:
        line = _digest_line(snapshot)
        if line and line not in seen:
            seen.add(line)
            out.append(line)
        if len(out) >= 8:
            break
    return out


def _extract_markdown_value(text: str, key: str) -> str:
    marker = f"| {key} |"
    for line in str(text or "").splitlines():
        if marker not in line:
            continue
        parts = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(parts) >= 2:
            return parts[1]
    return ""


def _orientation_facts(tool_name: str, obj) -> list[dict]:
    """Extract compact orientation facts from non-event context tools.

    Orientation facts help the model carry case/alert pivots forward without
    pretending case records are SIEM events or copying full case descriptions into
    evidence snapshots.
    """
    if not isinstance(obj, dict):
        return []
    if tool_name == "get_case":
        description = str(obj.get("description") or "")
        fact = {
            "source": "case",
            "case_id": str(obj.get("_id") or obj.get("id") or ""),
            "title": _clip(obj.get("title"), 160),
            "alert_time": _extract_markdown_value(description, "@timestamp"),
            "host": _extract_markdown_value(description, "agent.name"),
            "host_ip": _extract_markdown_value(description, "agent.ip"),
            "src_ip": _extract_markdown_value(description, "data.srcip"),
            "url": _extract_markdown_value(description, "data.url"),
            "rule_id": _extract_markdown_value(description, "rule.id"),
            "rule_description": _extract_markdown_value(description, "rule.description"),
        }
        compact = {key: value for key, value in fact.items() if value}
        return [compact] if compact else []
    if tool_name == "list_case_alerts":
        out: list[dict] = []
        for alert in (obj.get("alerts") or [])[:5]:
            if not isinstance(alert, dict):
                continue
            tags = alert.get("tags") or []
            tag_map = {}
            for tag in tags:
                if isinstance(tag, str) and "=" in tag:
                    key, value = tag.split("=", 1)
                    tag_map[key] = value
            fact = {
                "source": "alert",
                "alert_id": str(alert.get("_id") or ""),
                "title": _clip(alert.get("title"), 160),
                "alert_time": str(alert.get("date_iso") or ""),
                "source_ref": str(alert.get("sourceRef") or ""),
                "host": tag_map.get("agent_name", ""),
                "host_ip": tag_map.get("agent_ip", ""),
                "rule_id": tag_map.get("rule", ""),
            }
            compact = {key: value for key, value in fact.items() if value}
            if compact:
                out.append(compact)
        return out
    return []


def _volume_regimes(obj) -> list[dict]:
    if not isinstance(obj, dict):
        return []
    bursts = obj.get("bursts") or []
    out: list[dict] = []
    for burst in bursts[:8]:
        if not isinstance(burst, dict):
            continue
        regime = {
            "start": str(burst.get("start") or ""),
            "end": str(burst.get("end") or ""),
            "peak_count": int(burst.get("peak_count") or 0),
            "total": int(burst.get("total") or 0),
        }
        compact = {key: value for key, value in regime.items() if value not in ("", 0)}
        if compact:
            out.append(compact)
    return out


def _artifact_labels(artifacts: list[object]) -> list[str]:
    out: list[str] = []
    for artifact in artifacts or []:
        kind = getattr(artifact, "kind", "")
        value = getattr(artifact, "value", "")
        if kind and value:
            out.append(f"{kind}:{value}")
    return out[:12]


def _path_family(value: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("/"):
        return ""
    parts = [part for part in text.split("/") if part]
    if len(parts) >= 2:
        return f"/{parts[0]}/*"
    if len(parts) == 1:
        return f"/{parts[0]}*"
    return ""


# ── Pivot candidate derivation, scoring, and dedup ──
def _broader_alternative(field: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lowered_field = str(field or "").strip().lower()
    if lowered_field == "url":
        return _path_family(text)
    if lowered_field == "command":
        first = text.split()[0] if text.split() else ""
        if first:
            return f"same command family as `{first}` in the same scoped window"
    if lowered_field == "rule_id":
        return "same detection family or raw-event representation in the same scoped window"
    if lowered_field in {"src_ip", "dst_ip"}:
        return f"same {lowered_field} with tighter time/behavior scope"
    if lowered_field in {"agent", "host", "host_ip"}:
        return f"same {lowered_field} in the adjacent time window"
    return ""


def _pivot_candidate(
    *,
    field: str,
    value: str,
    source_level: str,
    role: str,
    confidence: str,
) -> dict | None:
    text = str(value or "").strip()
    if not field or not text:
        return None
    pivot = {
        "field": field,
        "value": text[:320],
        "source_level": source_level,
        "role": role,
        "confidence": confidence,
        "status": "active",
        "failure_count": 0,
        "last_failure_reason": "",
        "broader_alternative": _broader_alternative(field, text),
    }
    return pivot


def _pivot_candidates_from_orientation(fact: dict) -> list[dict]:
    if not isinstance(fact, dict):
        return []
    source_level = "case" if fact.get("source") == "case" else "alert_aggregate"
    rule_id = str(fact.get("rule_id") or "").strip()
    out: list[dict] = []
    for field in ("src_ip", "host", "host_ip", "rule_id"):
        candidate = _pivot_candidate(
            field=field,
            value=str(fact.get(field) or ""),
            source_level=source_level,
            role="anchor",
            confidence="medium",
        )
        if candidate:
            out.append(candidate)
    url_value = str(fact.get("url") or "").strip()
    if url_value:
        role = "exemplar" if source_level == "case" or rule_id in _CASE_URL_EXEMPLAR_RULE_IDS else "hypothesis"
        out.append(_pivot_candidate(
            field="url",
            value=url_value,
            source_level=source_level,
            role=role,
            confidence="low" if role == "exemplar" else "medium",
        ))
    return [candidate for candidate in out if isinstance(candidate, dict)]


def _pivot_candidates_from_snapshot(snapshot: dict) -> list[dict]:
    if not isinstance(snapshot, dict):
        return []
    out: list[dict] = []
    field_roles = {
        "src_ip": ("anchor", "high"),
        "dst_ip": ("anchor", "high"),
        "agent": ("anchor", "high"),
        "rule_id": ("hypothesis", "medium"),
        "user": ("hypothesis", "medium"),
        "url": ("discriminator", "high"),
        "command": ("discriminator", "high"),
    }
    for field, (role, confidence) in field_roles.items():
        candidate = _pivot_candidate(
            field=field,
            value=str(snapshot.get(field) or ""),
            source_level="raw_event",
            role=role,
            confidence=confidence,
        )
        if candidate:
            out.append(candidate)
    return out


def _dedupe_pivots(pivots: list[dict]) -> list[dict]:
    best_by_key: dict[str, dict] = {}
    for pivot in pivots:
        if not isinstance(pivot, dict):
            continue
        key = _pivot_key(pivot.get("field") or "", pivot.get("value") or "")
        if not key:
            continue
        current = best_by_key.get(key)
        score = (
            _PIVOT_SOURCE_SCORE.get(str(pivot.get("source_level") or ""), 0),
            _PIVOT_ROLE_SCORE.get(str(pivot.get("role") or ""), 0),
            _PIVOT_CONF_SCORE.get(str(pivot.get("confidence") or ""), 0),
        )
        if current is None:
            best_by_key[key] = pivot
            continue
        current_score = (
            _PIVOT_SOURCE_SCORE.get(str(current.get("source_level") or ""), 0),
            _PIVOT_ROLE_SCORE.get(str(current.get("role") or ""), 0),
            _PIVOT_CONF_SCORE.get(str(current.get("confidence") or ""), 0),
        )
        if score > current_score:
            best_by_key[key] = pivot
    return list(best_by_key.values())[:12]


def _dedupe(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ── Signals, recommended moves, and error recovery ──
def _error_recovery(tool_name: str, raw) -> dict | None:
    text = ""
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("Error:"):
            text = stripped
    else:
        obj = _load(raw)
        if isinstance(obj, dict) and obj.get("error"):
            text = str(obj.get("error") or "").strip()
    if not text:
        return None

    recovery = {
        "tool": tool_name,
        "error": _clip(text, 500),
        "signal": "TOOL_ERROR",
    }
    invalid = _INVALID_TIME_RE.search(text)
    if invalid:
        recovery["signal"] = "INVALID_TIME_WINDOW"
        recovery["requested_window"] = {"from": invalid.group(1), "to": invalid.group(2)}
    task_window = _TASK_WINDOW_RE.search(text)
    if task_window:
        recovery["required_window"] = {"from": task_window.group(1), "to": task_window.group(2)}
    return recovery


def _recommended_moves(signals: list[str]) -> list[str]:
    mapping = {
        "TRUNCATED": "narrow the query before trusting the sample",
        "SATURATED": "shrink the time window instead of changing the profile interval",
        "MULTI_REGIME": "compare candidate regimes against the alert anchor before narrowing",
        "FLOODED": "scope the search by rule.groups or a more specific discriminator",
        "EMPTY": "widen or pivot only after confirming the searched artifact and window were correct",
        "NO_NEW_EVIDENCE": "change the angle instead of repeating the same query shape",
        "ORIENTATION_ONLY": "run a concrete SIEM evidence query for this task objective",
        "WRONG_REPRESENTATION": "retrieve raw events after profiling instead of concluding from aggregates",
        "INVALID_TIME_WINDOW": "repeat the intended SIEM query inside the claimed task's absolute time window",
        "TOOL_ERROR": "recover from the concrete tool error before changing investigative direction",
    }
    return [mapping[s] for s in signals if s in mapping]


def _signals_for_result(tool_name: str, raw, obj, *, evidence_tools_used: set[str]) -> list[str]:
    signals: list[str] = []
    if tool_name in _SEARCH_TOOLS and isinstance(obj, dict):
        hits = extract_hit_count(raw)
        if obj.get("truncated") or obj.get("total_relation") == "gte":
            signals.append("TRUNCATED")
        if obj.get("rule_groups_breakdown"):
            signals.append("FLOODED")
        if hits == 0:
            signals.append("EMPTY")
    if tool_name == "get_event_volume" and isinstance(obj, dict):
        bursts = obj.get("bursts") or []
        if len(bursts) > 1:
            signals.append("MULTI_REGIME")
        elif obj.get("saturated"):
            signals.append("SATURATED")
        if int(obj.get("total") or 0) == 0:
            signals.append("EMPTY")
    if tool_name == "profile_field" and isinstance(obj, dict):
        values = obj.get("values") or obj.get("top_values") or []
        if not values:
            signals.append("EMPTY")
    if evidence_tools_used and evidence_tools_used.issubset(_PROFILE_TOOLS):
        signals.append("WRONG_REPRESENTATION")
    return signals


def _discriminator_from_result(obj) -> dict | None:
    """Extract the selectivity discriminator from a flooded search result: the field the
    events vary along, its dominant flood value, the available minority candidates, and
    any returned sample event ids. None if the result carries no usable discriminator.
    This is how the flood-deviation axis reaches `interpret`, which then routes the raw
    sample into the next-step instruction the agent actually obeys."""
    if not isinstance(obj, dict):
        return None
    smap = obj.get("selectivity_map") or []
    disc = next(
        (e for e in smap if e.get("role") == "discriminator" and e.get("minorities")),
        None,
    )
    if not disc:
        return None
    minorities = disc.get("minorities") or []
    rarest = minorities[-1].get("value") if minorities else None
    minority_values = [item.get("value") for item in minorities if isinstance(item, dict) and item.get("value") is not None]
    sample = obj.get("minority_sample") or []
    sample_ids = [h.get("_id") for h in sample if isinstance(h, dict) and h.get("_id")]
    return {
        "field": disc.get("field"),
        "dominant": disc.get("dominant"),
        "minority": rarest,
        "minority_values": minority_values[:8],
        "sample_event_ids": sample_ids[:8],
    }


def build_observation(
    tool_runs: list[dict],
    *,
    prior_observation: dict | None = None,
    objective: str = "",
) -> dict:
    """Summarize one tool batch into a normalized observation contract."""
    tools = [str(run.get("name") or "") for run in tool_runs]
    evidence_tools_used = {
        name for name in tools
        if name in _EVIDENCE_TOOLS and not run_is_error(next(r for r in tool_runs if r.get("name") == name))
    }
    signals: list[str] = []
    event_ids: list[str] = []
    new_artifacts: list[str] = []
    evidence_snapshots: list[dict] = []
    orientation_facts: list[dict] = []
    pivot_candidates: list[dict] = []
    volume_regimes: list[dict] = []
    error_recoveries: list[dict] = []
    summaries: list[str] = []
    hit_counts: list[int] = []
    discriminators: list[dict] = []
    time_windows: list[dict] = []
    query_focuses: list[dict] = []
    trials: list[dict] = []

    for run in tool_runs:
        tool_name = str(run.get("name") or "")
        args = run.get("args") or {}
        window = _tool_time_window(tool_name, args)
        if window:
            time_windows.append(window)
        focus = _tool_query_focus(tool_name, args)
        if focus:
            query_focuses.append(focus)
        raw = run.get("raw")
        obj = _load(raw)
        recovery = _error_recovery(tool_name, raw)
        if recovery:
            error_recoveries.append(recovery)
            signals.append(str(recovery.get("signal") or "TOOL_ERROR"))
            summaries.append(f"{tool_name} error: {recovery.get('signal')}")
            trial = _trial_record(focus, window, "error", None)
            if trial:
                trials.append(trial)
            continue
        tool_signals = _signals_for_result(
            tool_name, raw, obj, evidence_tools_used=evidence_tools_used
        )
        signals.extend(tool_signals)
        run_hits = extract_hit_count(raw) if tool_name in _SEARCH_TOOLS else None
        # Compute the event snapshots once (also reused below): the trial keeps a small
        # semantic digest of what THIS query retrieved so its meaning survives after the
        # events leave the current observation window.
        snapshots = _evidence_snapshots(tool_name, obj)
        trial = _trial_record(
            focus, window,
            _trial_outcome(tool_signals, run_hits, is_error=False,
                           has_events=bool(_event_ids(obj))),
            run_hits,
            evidence=_evidence_digest(snapshots),
        )
        if trial:
            trials.append(trial)
        if tool_name in _SEARCH_TOOLS and isinstance(obj, dict):
            hits = extract_hit_count(raw)
            if hits is not None:
                hit_counts.append(hits)
                summaries.append(f"{tool_name}={hits} hit(s)")
            disc = _discriminator_from_result(obj)
            if disc:
                discriminators.append(disc)
        elif tool_name == "get_event_volume" and isinstance(obj, dict):
            total = int(obj.get("total") or 0)
            summaries.append(f"get_event_volume={total} event(s)")
            regimes = _volume_regimes(obj)
            if regimes:
                summaries.append(f"regimes={len(regimes)}")
        event_ids.extend(_event_ids(obj))
        facts = _orientation_facts(tool_name, obj)
        evidence_snapshots.extend(snapshots)
        orientation_facts.extend(facts)
        for snapshot in snapshots:
            pivot_candidates.extend(_pivot_candidates_from_snapshot(snapshot))
        for fact in facts:
            pivot_candidates.extend(_pivot_candidates_from_orientation(fact))
        volume_regimes.extend(_volume_regimes(obj))
        new_artifacts.extend(_artifact_labels(run.get("artifacts") or []))

    evidence_markers = _dedupe([f"event:{eid}" for eid in event_ids] + new_artifacts)
    signals = _dedupe(signals)

    evidence_queries = sum(
        1 for run in tool_runs
        if str(run.get("name") or "") in _EVIDENCE_TOOLS and not run_is_error(run)
    )
    if evidence_queries == 0:
        signals = _dedupe(signals + ["ORIENTATION_ONLY"])
    if error_recoveries and "ORIENTATION_ONLY" in signals:
        signals = [s for s in signals if s != "ORIENTATION_ONLY"]

    if "EMPTY" in signals and any(s in signals for s in ("TRUNCATED", "FLOODED")):
        signals = [s for s in signals if s != "EMPTY"]

    prior_markers = set((prior_observation or {}).get("evidence_markers") or [])
    if evidence_queries > 0 and not evidence_markers:
        if prior_observation and (prior_observation.get("objective") or "") == objective:
            signals = _dedupe(signals + ["NO_NEW_EVIDENCE"])
    elif prior_markers and set(evidence_markers).issubset(prior_markers):
        if prior_observation and (prior_observation.get("objective") or "") == objective:
            signals = _dedupe(signals + ["NO_NEW_EVIDENCE"])

    advanced_objective = bool(evidence_markers) and not any(s in _STRONG_SIGNALS for s in signals)
    if evidence_queries > 0 and "EMPTY" not in signals and "WRONG_REPRESENTATION" not in signals:
        advanced_objective = advanced_objective or not any(
            s in signals for s in ("TRUNCATED", "SATURATED", "FLOODED")
        )

    evidence_digest = _evidence_digest(evidence_snapshots)
    summary = ", ".join(summaries[:3]) if summaries else "no concrete evidence returned"
    # Fold the top retrieved event into the propagated summary so semantic content
    # (not just a hit count) survives into the ledger, the interpret note, and the
    # deterministic fallback path — the model-independent channel.
    if evidence_digest:
        summary = f"{summary} — top: {evidence_digest[0][:200]}"
    if signals:
        summary = f"{summary}; signals={', '.join(signals)}"

    # The flood's deviation axis (prefer one whose minority-event sample was returned).
    discriminator = next(
        (d for d in discriminators if d.get("sample_event_ids")),
        discriminators[0] if discriminators else None,
    )
    moves = _recommended_moves(signals)
    if discriminator and discriminator.get("field") and discriminator.get("minority") is not None:
        values = ", ".join(str(v) for v in (discriminator.get("minority_values") or [])[:8])
        sample_ids = ", ".join(str(v) for v in (discriminator.get("sample_event_ids") or [])[:6])
        sample_part = f" sample events: {sample_ids};" if sample_ids else ""
        moves = moves + [
            f"the residue is on `{discriminator['field']}` with minority candidates "
            f"{values or discriminator['minority']};{sample_part} inspect and decode the "
            "provided minority sample first, rank candidates by semantic fit to the task "
            f"objective, then query `{discriminator['field']}=<chosen value>` or "
            f"`must_not {discriminator['field']}={discriminator['dominant']}` only if the "
            "sample is insufficient or scope must be enumerated"
        ]

    return {
        "objective": objective,
        "tools": tools,
        "evidence_queries": evidence_queries,
        "advanced_objective": advanced_objective,
        "signals": signals,
        "summary": summary,
        "discriminator": discriminator,
        "recommended_moves": moves,
        "error_recoveries": error_recoveries[:6],
        "new_artifacts": new_artifacts[:8],
        "event_ids": event_ids[:8],
        "evidence_markers": evidence_markers[:12],
        "evidence_digest": evidence_digest,
        "evidence_snapshots": evidence_snapshots[:8],
        "orientation_facts": orientation_facts[:8],
        "pivot_candidates": _dedupe_pivots(pivot_candidates),
        "volume_regimes": volume_regimes[:8],
        "hit_counts": hit_counts[:8],
        "time_windows": time_windows[:8],
        "query_focuses": query_focuses[:8],
        "trials": trials[:8],
    }


def run_is_error(run: dict) -> bool:
    raw = run.get("raw")
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("Error:"):
            return True
    obj = _load(raw)
    return isinstance(obj, dict) and "error" in obj
