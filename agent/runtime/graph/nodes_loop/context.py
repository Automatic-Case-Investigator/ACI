from __future__ import annotations

"""Queue-context rendering and task/tool time-window derivation."""

from ..state import AgentState
from langchain_core.messages import ToolMessage
from ..timeutil import _find_timestamp_range
from ..timeutil import _format_dt
from ..toolio import _list_tasks
from ..timeutil import _parse_dt
from datetime import datetime
import json
import re
from datetime import timedelta

from ._const import _QUEUE_CONTEXT_MAX_TASKS, _QUEUE_CONTEXT_SNIPPET_CHARS, _SIEM_TIME_WINDOW_TOOLS, _TASK_WINDOW_RE


# ── Queue context rendering + task/tool time-window derivation and guard ──
def _format_queue_context(tasks: list[dict]) -> str:
    if not tasks:
        return "\n\n---\n**Current Task Queue:**\n- No queued tasks found.\n---"
    lines = ["\n\n---", "**Current Task Queue (check before proposing New Leads):**"]
    for task in tasks[:_QUEUE_CONTEXT_MAX_TASKS]:
        status = task.get("status") or "unknown"
        priority = task.get("priority", "?")
        title = (task.get("title") or "(untitled)").strip()
        desc = " ".join((task.get("description") or "").split())
        if len(desc) > _QUEUE_CONTEXT_SNIPPET_CHARS:
            desc = desc[:_QUEUE_CONTEXT_SNIPPET_CHARS].rstrip() + "..."
        suffix = f" — {desc}" if desc else ""
        lines.append(f"- [{status} P{priority}] {title}{suffix}")
    if len(tasks) > _QUEUE_CONTEXT_MAX_TASKS:
        lines.append(
            f"- ... {len(tasks) - _QUEUE_CONTEXT_MAX_TASKS} more task(s) omitted"
        )
    lines.append(
        "Only propose New Leads that are evidence-backed, not already covered above, "
        "and include title, pivots, evidence, and a queue-relative numeric priority."
    )
    lines.append("---")
    return "\n".join(lines)


async def _queue_context_for_state(state: AgentState, tools: list) -> str:
    """Return a compact queue snapshot that helps investigation avoid duplicate leads."""
    if state["agent_name"] != "investigation":
        return ""
    tasks = await _list_tasks(
        tools, state["case_id"], state["run_id"], state["agent_name"]
    )
    return _format_queue_context(tasks)


def _task_time_window(task: dict | None) -> tuple[datetime, datetime] | None:
    text = (task or {}).get("description") or ""
    match = _TASK_WINDOW_RE.search(text)
    if not match:
        return None
    start, end = _parse_dt(match.group(1)), _parse_dt(match.group(2))
    if start and end and end > start:
        return start, end
    return None


def _tool_time_window(tool_name: str, args: dict) -> tuple[datetime, datetime] | None:
    if tool_name == "get_event_volume":
        start, end = args.get("start_time"), args.get("end_time")
    elif tool_name in {"correlate_entity", "correlate_techniques"}:
        start, end = args.get("start_time"), args.get("end_time")
    else:
        tr = args.get("time_range") if isinstance(args.get("time_range"), dict) else {}
        start, end = tr.get("from"), tr.get("to")
        if not (start and end):
            start, end = _find_timestamp_range(args.get("query"))
    start_dt, end_dt = _parse_dt(start), _parse_dt(end)
    if start_dt and end_dt and end_dt > start_dt:
        return start_dt, end_dt
    return None


def _incident_anchor_from_messages(messages: list) -> tuple[datetime, str] | None:
    """Return the case/alert incident anchor seen in the current task history.

    Precedence is intentionally event-time first. TheHive `createdAt`/`_createdAt`
    never participate; those are case lifecycle/import timestamps.
    """
    candidates: list[tuple[int, datetime, str]] = []
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            data = json.loads(getattr(msg, "content", "") or "")
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        name = getattr(msg, "name", "")
        if name == "get_case" and isinstance(data, dict):
            found_case_anchor = False
            for key, priority in (
                ("incident_time_iso", 0),
                ("date_iso", 1),
                ("date", 2),
            ):
                dt = _parse_dt(data.get(key))
                if dt:
                    candidates.append((priority, dt, f"case.{key}"))
                    found_case_anchor = True
                    break
            if not found_case_anchor:
                # Some imports only carry the raw Wazuh event in the markdown
                # description. Pull @timestamp from that text before considering
                # any lifecycle field.
                desc = str(data.get("description") or "")
                marker = re.search(
                    r"@\s*timestamp\s*\|\s*([0-9T:.\-+Z]+)", desc, re.IGNORECASE
                )
                if marker:
                    dt = _parse_dt(marker.group(1))
                    if dt:
                        candidates.append((3, dt, "case.description.@timestamp"))
        elif name == "list_case_alerts" and isinstance(data, dict):
            tr = data.get("time_range") or {}
            for key, priority in (("first", 4), ("last", 5)):
                dt = _parse_dt(tr.get(key))
                if dt:
                    candidates.append((priority, dt, f"alerts.time_range.{key}"))
                    break
            for alert in data.get("alerts") or []:
                if isinstance(alert, dict):
                    dt = _parse_dt(alert.get("date_iso"))
                    if dt:
                        candidates.append((6, dt, "alert.date_iso"))
                        break
    if not candidates:
        return None
    _, dt, source = sorted(candidates, key=lambda item: item[0])[0]
    return dt, source


def _time_window_guard(
    tool_name: str, args: dict, state: AgentState, messages: list
) -> str | None:
    if tool_name not in _SIEM_TIME_WINDOW_TOOLS:
        return None
    requested = _tool_time_window(tool_name, args)
    if requested is None:
        return None
    req_start, req_end = requested
    # The agent may widen a task's declared window up to the configured vicinity window
    # on either side. The task window is a STARTING hint (often a tight pinpoint for a
    # "retrieve the exact event" task), NOT a hard cap: an investigation legitimately
    # needs to look at surrounding context. The guard only exists to block a query on the
    # wrong day/year or a TheHive createdAt timestamp, so bound it by the vicinity window,
    # not the narrow task box. (Diagnosed: a 2-minute task window under a zero-tolerance
    # guard trapped the agent in a ~60-call `invalid time range` loop with no escape.)
    vicinity = timedelta(
        hours=max(1, int(state.get("default_vicinity_window_hours") or 24))
    )
    task_window = _task_time_window(state.get("current_task"))
    if task_window is not None:
        task_start, task_end = task_window
        allowed_start, allowed_end = task_start - vicinity, task_end + vicinity
        if req_start < allowed_start or req_end > allowed_end:
            vicinity_h = int(vicinity.total_seconds() // 3600)
            return (
                "Invalid SIEM time range: "
                f"{_format_dt(req_start)} to {_format_dt(req_end)}. "
                f"The claimed task specifies {_format_dt(task_start)} to {_format_dt(task_end)}. "
                f"You may widen up to +/-{vicinity_h}h around it (the configured vicinity window, "
                f"i.e. {_format_dt(allowed_start)} to {_format_dt(allowed_end)}), but this request "
                "falls outside that bound. Do not use TheHive createdAt/_createdAt as event time."
            )
        return None
    anchor = _incident_anchor_from_messages(messages)
    if anchor is None:
        return None
    anchor_dt, source = anchor
    tolerance = timedelta(
        days=max(2, int(state.get("default_vicinity_window_hours") or 24) // 24 + 2)
    )
    if req_end < anchor_dt - tolerance or req_start > anchor_dt + tolerance:
        return (
            "Invalid SIEM time range: "
            f"{_format_dt(req_start)} to {_format_dt(req_end)}. "
            f"This case's incident anchor is {_format_dt(anchor_dt)} from {source}. "
            "Use the case `date` / alert timestamp, not TheHive createdAt/_createdAt."
        )
    return None
