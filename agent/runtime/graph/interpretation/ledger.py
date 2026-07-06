"""Ledger field coercion + merge helpers: the durable per-task memory transforms."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re

from ._const import _CONFIRMED_FINDINGS_KEEP, _DEFAULT_STOP_CONDITION, _FOCUS_STAGNANT_RETRIES, _JSON_OBJECT_RE, _QUERY_TRIALS_KEEP, _RECENT_QUERY_FOCUSES_KEEP, _RECENT_TIME_WINDOWS_KEEP, _SECTION_LABELS, _STOP_STATE_RE, _WINDOW_OVERLAP_RATIO, _WINDOW_STAGNANT_RETRIES


def _default_ledger(task: dict | None) -> dict:
    title = (task or {}).get("title") or ""
    desc = (task or {}).get("description") or ""
    return {
        "objective": title or desc[:240],
        # One field per concept (see ledger-simplification): `hypothesis` (not also
        # `working_hypothesis`), `evidence_summary` (the last batch's reading — not also
        # `last_observation`), `blocker` (not also `current_focus`), `next_step_instruction`
        # (the imperative think follows — not also `next_step`).
        "hypothesis": "",
        "evidence_summary": "",
        "stop_state": "continue",
        "next_action": "retrieve_specific_event",
        "next_step_instruction": "",
        "next_adjacent_evidence_path": {},
        "forbidden_repeats": [],
        "blocker": "",
        "evidence_state": "orientation",
        "evidence_found": [],
        "confirmed_findings": [],
        "remaining_gaps": [],
        "stop_condition": _DEFAULT_STOP_CONDITION,
        "stop_reason": "",
        "primary_pivot": {},
        "active_pivots": [],
        "next_pivot_strategy": "keep",
        "why_current_pivot_failed": "",
        "recent_time_windows": [],
        "recent_query_focuses": [],
        "query_trials": [],
    }
def _parse_json_object(text: str) -> dict | None:
    raw = (text or "").strip()
    if not raw:
        return None
    match = _JSON_OBJECT_RE.search(raw)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
    except (TypeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None
def _extract_section(text: str, labels: tuple[str, ...]) -> str:
    lines = str(text or "").splitlines()
    label_positions: list[int] = []
    lowered = [line.strip().lower().strip(":") for line in lines]
    wanted = {label.lower() for label in labels}
    for idx, line in enumerate(lowered):
        if line in wanted:
            label_positions.append(idx)
    if not label_positions:
        return ""
    start = label_positions[0] + 1
    end = len(lines)
    all_labels = {
        label.lower()
        for group in _SECTION_LABELS.values()
        for label in group
    }
    for idx in range(start, len(lines)):
        lowered_line = lines[idx].strip().lower().strip(":")
        if lowered_line in all_labels:
            end = idx
            break
    content = "\n".join(lines[start:end]).strip()
    return " ".join(content.split())[:1200]
def _parse_interpretation_text(text: str) -> dict | None:
    raw = str(text or "").strip()
    if not raw:
        return None
    parsed = _parse_json_object(raw)
    if isinstance(parsed, dict):
        return parsed
    out: dict = {}
    for key, labels in _SECTION_LABELS.items():
        value = _extract_section(raw, labels)
        if value:
            out[key] = value
    if not out:
        return None
    stop_text = str(out.get("stop_state") or "")
    match = _STOP_STATE_RE.search(stop_text)
    if match:
        out["stop_state"] = match.group(1).lower()
    advance = str(out.get("advanced_objective") or "").lower()
    if advance:
        out["advanced_objective"] = advance.startswith("y") or "material" in advance
    return out
def _coerce_string_list(value, *, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = " ".join(str(item or "").split())
        if text:
            out.append(text[:500])
    return out[:limit]
def _merge_string_lists(existing, new, *, limit: int = 12) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in _coerce_string_list(existing, limit=limit) + _coerce_string_list(new, limit=limit):
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged[:limit]
def _coerce_confirmed_findings(value, *, limit: int = _CONFIRMED_FINDINGS_KEEP) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if isinstance(item, str):
            summary = " ".join(item.split())
            if not summary:
                continue
            out.append({
                "summary": summary[:800],
                "event_ids": [],
                "time_range": {},
                "entities": [],
                "kind": "confirmed_evidence",
                "confidence": "medium",
                "status": "confirmed",
            })
            continue
        if not isinstance(item, dict):
            continue
        summary = " ".join(str(item.get("summary") or item.get("text") or "").split())
        if not summary:
            continue
        event_ids = _coerce_string_list(item.get("event_ids"), limit=8)
        entities = _coerce_string_list(item.get("entities"), limit=12)
        time_range = item.get("time_range") if isinstance(item.get("time_range"), dict) else {}
        clean_range = {}
        for key in ("from", "to"):
            text = " ".join(str(time_range.get(key) or "").split())
            if text:
                clean_range[key] = text[:80]
        out.append({
            "summary": summary[:800],
            "event_ids": event_ids,
            "time_range": clean_range,
            "entities": entities,
            "kind": " ".join(str(item.get("kind") or "confirmed_evidence").split())[:80],
            "confidence": " ".join(str(item.get("confidence") or "medium").split())[:40],
            "status": "confirmed",
        })
    return out[-limit:]
def _finding_key(finding: dict) -> str:
    event_ids = ",".join(sorted(str(e).lower() for e in (finding.get("event_ids") or [])))
    summary = re.sub(r"\s+", " ", str(finding.get("summary") or "").strip().lower())
    return event_ids or summary[:240]
def _merge_confirmed_findings(existing, new, *, limit: int = _CONFIRMED_FINDINGS_KEEP) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()
    for item in _coerce_confirmed_findings(existing, limit=limit) + _coerce_confirmed_findings(new, limit=limit):
        key = _finding_key(item)
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged[-limit:]
def _time_range_from_snapshots(snapshots: list[dict]) -> dict:
    values = [
        str(item.get("timestamp") or "").strip()
        for item in snapshots
        if isinstance(item, dict) and str(item.get("timestamp") or "").strip()
    ]
    if not values:
        return {}
    return {"from": min(values), "to": max(values)}
def _entities_from_snapshots(snapshots: list[dict]) -> list[str]:
    entities: list[str] = []
    for item in snapshots:
        if not isinstance(item, dict):
            continue
        for field in ("agent", "user", "src_ip", "dst_ip", "rule_id", "command", "url"):
            value = " ".join(str(item.get(field) or "").split())
            if value:
                entities.append(f"{field}={value[:160]}")
    return _merge_string_lists([], entities, limit=12)
def _confirmed_findings_from_observation(observation: dict, parsed: dict | None = None) -> list[dict]:
    parsed = parsed or {}
    parsed_advanced = parsed.get("advanced_objective")
    if isinstance(parsed_advanced, str):
        lowered = parsed_advanced.strip().lower()
        parsed_advanced = lowered.startswith("y") or "material" in lowered or lowered == "true"
    advanced = bool(parsed_advanced or observation.get("advanced_objective"))
    event_ids = _coerce_string_list(observation.get("event_ids"), limit=8)
    snapshots = [s for s in (observation.get("evidence_snapshots") or []) if isinstance(s, dict)]
    if not (advanced and (event_ids or snapshots or observation.get("evidence_markers"))):
        return []

    summaries = _coerce_string_list(parsed.get("evidence_found"), limit=6)
    if not summaries:
        what_showed = " ".join(str(parsed.get("what_showed") or "").split())
        if what_showed:
            summaries = [what_showed]
    if not summaries:
        digest = _coerce_string_list(observation.get("evidence_digest"), limit=1)
        summaries = digest or _coerce_string_list([observation.get("summary")], limit=1)

    out: list[dict] = []
    for summary in summaries[:3]:
        out.append({
            "summary": summary,
            "event_ids": event_ids,
            "time_range": _time_range_from_snapshots(snapshots),
            "entities": _entities_from_snapshots(snapshots),
            "kind": "raw_event_evidence",
            "confidence": "high" if event_ids or snapshots else "medium",
            "status": "confirmed",
        })
    return out
def _parse_window_dt(value) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
def _format_window_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
def _coerce_time_windows(value, *, limit: int = _RECENT_TIME_WINDOWS_KEEP) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        start = _parse_window_dt(item.get("from"))
        end = _parse_window_dt(item.get("to"))
        if not (start and end and end > start):
            continue
        out.append({
            "tool": " ".join(str(item.get("tool") or "").split())[:80],
            "from": _format_window_dt(start),
            "to": _format_window_dt(end),
        })
    return out[-limit:]
def _window_tuple(item: dict) -> tuple[datetime, datetime] | None:
    start = _parse_window_dt(item.get("from"))
    end = _parse_window_dt(item.get("to"))
    if start and end and end > start:
        return start, end
    return None
def _overlap_ratio(a: dict, b: dict) -> float:
    aw = _window_tuple(a)
    bw = _window_tuple(b)
    if not aw or not bw:
        return 0.0
    start = max(aw[0], bw[0])
    end = min(aw[1], bw[1])
    if end <= start:
        return 0.0
    overlap = (end - start).total_seconds()
    shorter = min((aw[1] - aw[0]).total_seconds(), (bw[1] - bw[0]).total_seconds())
    return overlap / shorter if shorter > 0 else 0.0
def _merge_recent_time_windows(existing, new, *, advanced: bool) -> list[dict]:
    current = _coerce_time_windows(new)
    if advanced:
        return current[-_RECENT_TIME_WINDOWS_KEEP:]
    merged = _coerce_time_windows(existing) + current
    return merged[-_RECENT_TIME_WINDOWS_KEEP:]
def _coerce_query_focuses(value, *, limit: int = _RECENT_QUERY_FOCUSES_KEEP) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        focus = " ".join(str(item.get("focus") or "").split())
        if not focus:
            continue
        out.append({
            "tool": " ".join(str(item.get("tool") or "").split())[:80],
            "focus": focus[:500],
        })
    return out[-limit:]
def _merge_recent_query_focuses(existing, new, *, advanced: bool) -> list[dict]:
    current = _coerce_query_focuses(new)
    if advanced:
        return current[-_RECENT_QUERY_FOCUSES_KEEP:]
    merged = _coerce_query_focuses(existing) + current
    return merged[-_RECENT_QUERY_FOCUSES_KEEP:]
def _detect_window_stagnation(ledger: dict, observation: dict, observation_retries: int) -> dict:
    current = _coerce_time_windows(observation.get("time_windows"))
    recent = _coerce_time_windows(ledger.get("recent_time_windows"))
    if observation.get("advanced_objective") or observation_retries < _WINDOW_STAGNANT_RETRIES or not current or not recent:
        return {}
    overlapping: list[dict] = []
    for prior in recent:
        if any(_overlap_ratio(prior, now) >= _WINDOW_OVERLAP_RATIO for now in current):
            overlapping.append(prior)
    if len(overlapping) < 1:
        return {}
    all_windows = overlapping + current
    parsed = [_window_tuple(item) for item in all_windows]
    parsed = [item for item in parsed if item]
    if not parsed:
        return {}
    covered_start = min(start for start, _ in parsed)
    covered_end = max(end for _, end in parsed)
    return {
        "covered_span": {
            "from": _format_window_dt(covered_start),
            "to": _format_window_dt(covered_end),
        },
        "recent_windows": all_windows[-_RECENT_TIME_WINDOWS_KEEP:],
        "reason": (
            "Repeated non-advancing evidence queries substantially overlapped the same "
            "covered time slice."
        ),
    }
def _detect_focus_stagnation(ledger: dict, observation: dict, observation_retries: int) -> dict:
    current = _coerce_query_focuses(observation.get("query_focuses"))
    recent = _coerce_query_focuses(ledger.get("recent_query_focuses"))
    if observation.get("advanced_objective") or observation_retries < _FOCUS_STAGNANT_RETRIES or not current or not recent:
        return {}
    prior = {item.get("focus") for item in recent}
    repeated = [item for item in current if item.get("focus") in prior]
    if not repeated:
        return {}
    return {
        "repeated_focuses": repeated[-_RECENT_QUERY_FOCUSES_KEEP:],
        "recent_focuses": (recent + current)[-_RECENT_QUERY_FOCUSES_KEEP:],
        "reason": (
            "Repeated non-advancing evidence queries reused the same keyword, DSL, "
            "or profile-field anchor."
        ),
    }
def _coerce_trials(value, *, limit: int = _QUERY_TRIALS_KEEP) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        disc = " ".join(str(item.get("discriminator") or "").split())
        window = " ".join(str(item.get("window") or "").split())
        if not disc and not window:
            continue
        rec = {
            "discriminator": disc[:500],
            "window": window[:120],
            "outcome": " ".join(str(item.get("outcome") or "").split())[:40] or "unknown",
            "count": max(1, int(item.get("count") or 1)),
        }
        if isinstance(item.get("hits"), int):
            rec["hits"] = item["hits"]
        evidence = [" ".join(str(line).split()) for line in (item.get("evidence") or []) if line]
        if evidence:
            rec["evidence"] = evidence[:3]
        out.append(rec)
    return out[-limit:]
def _merge_query_trials(existing, new, *, limit: int = _QUERY_TRIALS_KEEP) -> list[dict]:
    """Accumulate this task's query trials. A repeated (discriminator, window) pair is not
    duplicated — its `count` is incremented and its latest outcome kept, so a dead shape
    shows as `… empty x14`, making the repetition glaring instead of scrolling past."""
    out = _coerce_trials(existing)
    index = {(t["discriminator"], t["window"]): t for t in out}
    for trial in _coerce_trials(new):
        key = (trial["discriminator"], trial["window"])
        prev = index.get(key)
        if prev is not None:
            prev["count"] += trial.get("count", 1)
            prev["outcome"] = trial["outcome"]
            if "hits" in trial:
                prev["hits"] = trial["hits"]
            # Keep the most recent non-empty event digest so the retrieved semantics of a
            # repeated shape are not lost when a later run of it returned nothing.
            if trial.get("evidence"):
                prev["evidence"] = trial["evidence"]
        else:
            index[key] = trial
            out.append(trial)
    return out[-limit:]
def _render_query_trials(trials: list[dict]) -> str:
    lines: list[str] = []
    for trial in _coerce_trials(trials)[-12:]:
        repeat = f" x{trial['count']}" if trial.get("count", 1) > 1 else ""
        hits = f" hits={trial['hits']}" if "hits" in trial else ""
        disc = trial.get("discriminator") or "(no discriminator)"
        window = trial.get("window") or "(no window)"
        lines.append(f"- [{trial.get('outcome', '?')}{repeat}] {disc} @ {window}{hits}")
        # The retrieved event semantics for this trial, so the interpreter can analyze what
        # each past query actually returned, not merely how many hits it got.
        for line in trial.get("evidence") or []:
            lines.append(f"    · {line}")
    return "\n".join(lines)
