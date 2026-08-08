from __future__ import annotations

"""Graph nodes that drive task seeding, claiming, reasoning, and tool execution."""

import json
import re
from datetime import datetime, timedelta

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ...agents.base import Handoff
from ...workspace.avfs_writer import update_memory_indexes
from ..analysis.artifacts import record_artifacts
from ..engine.seeder_runner import run_seeder
from ..infra.logbus import emit, src_label, summarize_args, summarize_result, summarize_think

from .board import _format_board_context
from .interpretation import _default_ledger
from .observation import build_observation
from .coverage import _count_evidence_queries
from .sanitize import _HARMONY_TOKEN_RE, _sanitize_history, _sanitize_message
from .state import AgentState
from .timeutil import _find_timestamp_range, _format_dt, _parse_dt
from .toolio import _call, _cancel_requested, _cap_tool_result, _compact_history, _emit_node_entry, _ensure_parent_dir, _ensure_workspace_dirs, _expand_tilde_args, _has_pending_tasks, _invoke_bound_model, _is_error_tool_result, _list_tasks, _model_tools_for_agent, _parse_claimed_task, _reclaim_stale_tasks, _should_compact, _tmap, _track_input_tokens



_QUEUE_CONTEXT_MAX_TASKS = 12
_QUEUE_CONTEXT_SNIPPET_CHARS = 120

# Per-task tool-call cap. A single task is not allowed to consume the whole run's
# budget: in a diagnosed live run one gap-check task spent 88 of ~100 calls, starving
# every later (higher-value) task. When a task reaches this many tool calls, `think`
# strips its tools and forces a wrap-up so the loop advances to the next task with
# whatever was found. Tuned well below the typical run budget so several tasks get a
# fair share, yet high enough that a legitimately deep task still completes.
_MAX_TASK_TOOL_CALLS = 50
_SIEM_TIME_WINDOW_TOOLS = frozenset({
    "search", "search_keyword", "profile_field", "get_event_volume",
    "correlate_entity", "correlate_techniques",
})
_CACHEABLE_READ_TOOLS = frozenset({
    "get_case",
    "get_alert",
    "list_case_alerts",
    "get_event",
    "get_event_volume",
    "profile_field",
    "search",
    "search_keyword",
})
_TASK_WINDOW_RE = re.compile(
    r"Time window:\s*`?([0-9T:.\-+Z]+)`?\s+to\s+`?([0-9T:.\-+Z]+)`?",
    re.IGNORECASE,
)


def _tool_cache_key(name: str, args: dict) -> str:
    return json.dumps({"tool": name, "args": args}, sort_keys=True, default=str)


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
        lines.append(f"- ... {len(tasks) - _QUEUE_CONTEXT_MAX_TASKS} more task(s) omitted")
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
    tasks = await _list_tasks(tools, state["case_id"], state["run_id"], state["agent_name"])
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
                marker = re.search(r"@\s*timestamp\s*\|\s*([0-9T:.\-+Z]+)", desc, re.IGNORECASE)
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


def _time_window_guard(tool_name: str, args: dict, state: AgentState, messages: list) -> str | None:
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
    vicinity = timedelta(hours=max(1, int(state.get("default_vicinity_window_hours") or 24)))
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
    tolerance = timedelta(days=max(2, int(state.get("default_vicinity_window_hours") or 24) // 24 + 2))
    if req_end < anchor_dt - tolerance or req_start > anchor_dt + tolerance:
        return (
            "Invalid SIEM time range: "
            f"{_format_dt(req_start)} to {_format_dt(req_end)}. "
            f"This case's incident anchor is {_format_dt(anchor_dt)} from {source}. "
            "Use the case `date` / alert timestamp, not TheHive createdAt/_createdAt."
        )
    return None



# ── Graph nodes: seed → claim → think → use_tools (the per-task tool loop) ──
async def seed(state: AgentState, config) -> dict:
    """Populate the initial task queue for triage or investigation runs."""
    tools = config["configurable"]["tools"]
    create = _tmap(tools).get("create_task")
    agent_name = state["agent_name"]

    src = src_label(agent_name)
    _emit_node_entry(src, "seed", state)
    emit(src, "note", f"seed case={state['case_id']} run={state['run_id']}")
    # Materialize the AVFS workspace folders the AVFS prompt directs the agent to
    # read, so prompt-directed reads return empty instead of erroring per task.
    if await _ensure_workspace_dirs(tools, _dbg=src):
        emit(src, "note", "workspace: ensured ~/sessions ~/tasks ~/memory ~/knowledge")
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)

    if agent_name == "triage":
        # Triage runs the flat loop (`triage_flat.triage_think`), which anchors on the
        # analyst's question directly and never claims from the queue, so there is no
        # task to seed. The objective text lives in `triage_flat.build_triage_objective`.
        pass

    else:
        # investigation: only seed if queue is empty
        already_seeded = await _has_pending_tasks(
            tools, state["case_id"], state["run_id"], state["agent_name"]
        )
        if not already_seeded:
            handoff = Handoff.from_dict(state.get("handoff"))
            if handoff is not None and not handoff.prior_investigation_report:
                # Normal triage handoff → dedicated seeder agent
                model = config["configurable"]["model"]
                await run_seeder(handoff, tools, model, vicinity_hours)
            elif handoff is not None:
                # Resume run (prior investigation report) → meta-task for open-gap re-seeding
                if create:
                    description = handoff.to_seed_text() + (
                        f"\n\nWhen an open gap does not already specify an absolute time window, "
                        f"derive one using this run's configured default vicinity window of "
                        f"±{vicinity_hours} hours around the anchor timestamp."
                    )
                    result = await _call(create, {
                        "title": "Populate investigation queue from triage handoff",
                        "description": description,
                        "priority": 100,
                    }, _dbg=src)
                    if _is_error_tool_result(result):
                        emit(src, "error", "seed: create_task FAILED", detail=str(result))
                    else:
                        emit(src, "note", "created resume handoff task")
            else:
                # No handoff — create a plain investigation task
                if create:
                    description = (
                        f"{state['question']}\n\n"
                        "Use available SIEM and SOAR capabilities to investigate. "
                        f"For nearby/vicinity event searches without an explicit absolute window, "
                        f"start from the configured default vicinity window of ±{vicinity_hours} "
                        "hours around the anchor timestamp. "
                        "Write findings to AVFS. "
                        "Create follow-up tasks for new evidence-backed leads. "
                        "When finished, post a report to the case system."
                    )
                    result = await _call(create, {
                        "title": f"Investigate {state['case_id']}",
                        "description": description,
                        "priority": 100,
                    }, _dbg=src)
                    if _is_error_tool_result(result):
                        emit(src, "error", "seed: create_task FAILED", detail=str(result))
                    else:
                        emit(src, "note", "created fallback investigation task")
        elif already_seeded:
            emit(src, "note", "queue already populated, skipping seed")

    return {}


async def claim(state: AgentState, config) -> dict:
    """Claim the next queued task, recovering stale claims once before giving up."""
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "claim", state)
    if await _cancel_requested(state["run_id"]):
        emit(src, "note", "cancel requested, stopping before next task claim")
        return {"status": "cancelled", "current_task": None}

    tools = config["configurable"]["tools"]
    claim_fn = _tmap(tools).get("claim_next")
    if claim_fn is None:
        return {"current_task": None}
    args = {
        "case_id": state["case_id"],
        "run_id": state["run_id"],
        "agent_name": state["agent_name"],
    }
    task = _parse_claimed_task(await _call(claim_fn, args, _dbg=src))
    if task is None:
        # Queue looks empty — but a stale `claimed` task may just be hidden from
        # claim_next. Recover any and retry once before giving up.
        recovered = await _reclaim_stale_tasks(tools, state, _dbg=src)
        if recovered:
            emit(src, "note", f"recovered {recovered} stale claimed task(s) — retrying claim")
            task = _parse_claimed_task(await _call(claim_fn, args, _dbg=src))
    if task:
        emit(src, "task", f"[P{task.get('priority', '?')}] {task.get('title', '?')}",
             detail=json.dumps(task, indent=2, default=str))
    else:
        emit(src, "note", "queue empty, moving to finish")
    # Snapshot the run-wide call counter so the per-task cap in `think` measures
    # calls spent on THIS task (tool_calls_made - task_call_floor).
    ledger = _default_ledger(task) if task else None
    return {
        "current_task": task,
        # THE COMPACTION SEAM. History is flat within a task and cleared here, at the
        # task boundary — a new objective starts with a clean context. What needs to
        # cross the boundary already does, via the findings board and the ledger's
        # confirmed findings.
        "messages": [],
        "task_call_floor": state["tool_calls_made"],
        "task_ledger": ledger,
        "last_confirmed_findings": [],
        "last_observation": None,
        "observation_retries": 0,
        "no_progress_cycles": 0,
    }


def _task_anchor(state: AgentState) -> str:
    """The task objective and reasoning contract — sent ONCE, as the task's message[1].

    Everything here is stable for the life of the task. Anything derived from the
    ledger changes every cycle and belongs in `_cycle_steering`, which is never
    persisted — so this message can never be re-read as a checklist to restart.
    """
    task = state.get("current_task") or {}
    text = f"**Task:** {task.get('title', '')}\n\n{task.get('description') or ''}".strip()
    text += (
        "\n\nReasoning contract:\n"
        "- Decide what evidence would actually answer this task before choosing tools.\n"
        "- Separate context, aggregate signal, direct evidence, and conclusion.\n"
        "- Prefer the next tool call that most directly tests the task objective.\n"
        "- Treat case or aggregate-alert exemplars as illustrative unless raw evidence "
        "upgrades them; prefer entity + time + behavior-family pivots over low-confidence "
        "exact strings.\n"
        "- Treat the interpretation note as advisory synthesis, not as a forced plan. "
        "Re-plan when the broader objective or evidence suggests a better move.\n"
        "- If a query returns a small scoped hit set, retrieve representative raw events "
        "before broadening to another entity.\n"
        "- If the current evidence only confirms one stage of activity, ask what happened "
        "next on the same asset and timeline before repeating the same-stage query.\n"
        "- Before choosing tools, compare current semantic evidence to the task objective. "
        "If it already satisfies the objective, synthesize the finding and query further "
        "only for explicitly unresolved subclaims.\n"
        "- If you are relying on inference instead of direct evidence, say so.\n\n"
        "Your own prior tool calls and their results are in this conversation — read them "
        "rather than re-running them. When the objective is answered, write the report as "
        "text using the mandatory format:\n\n## Findings\n## Hypotheses\n## New Leads"
    )
    return text


async def _cycle_steering(state: AgentState, tools: list) -> str:
    """This cycle's ledger-derived guidance plus live board/queue state.

    Appended to the model call but NOT persisted, so instructions never accumulate
    in the durable history and the model's context stays evidence.
    """
    ledger = state.get("task_ledger") or {}
    parts: list[str] = []

    if ledger.get("next_step_instruction"):
        parts.append(
            "Your REQUIRED next step (not merely advisory):\n"
            f"{ledger['next_step_instruction']}"
        )

    forbidden = [
        str(item).strip() for item in (ledger.get("forbidden_repeats") or [])
        if str(item).strip()
    ]
    if forbidden:
        parts.append(
            "Do not repeat without first explaining why the ledger is wrong:\n"
            + "\n".join(f"- {item}" for item in forbidden[:8])
        )

    if ledger.get("evidence_state") or ledger.get("stop_condition"):
        parts.append(
            "Current evidence path:\n"
            f"- Evidence state: {ledger.get('evidence_state') or 'orientation'}\n"
            f"- Stop condition: {ledger.get('stop_condition') or 'direct evidence or well-scoped confirmed negative'}"
        )

    if ledger.get("blocker") or ledger.get("hypothesis"):
        lines = ["Current interpretation:"]
        if ledger.get("blocker"):
            lines.append(f"- Open blocker: {ledger.get('blocker')}")
        if ledger.get("hypothesis"):
            lines.append(f"- Working hypothesis: {ledger.get('hypothesis')}")
        parts.append("\n".join(lines))

    primary_pivot = ledger.get("primary_pivot") or {}
    if isinstance(primary_pivot, dict) and primary_pivot.get("field") and primary_pivot.get("value"):
        lines = [
            "Current pivot state:",
            f"- Primary pivot: {primary_pivot.get('field')}={primary_pivot.get('value')} "
            f"({primary_pivot.get('source_level') or 'unknown'}, "
            f"{primary_pivot.get('role') or 'unknown'}, "
            f"{primary_pivot.get('confidence') or 'unknown'}, "
            f"status={primary_pivot.get('status') or 'active'}, "
            f"failures={primary_pivot.get('failure_count') or 0})",
        ]
        if primary_pivot.get("broader_alternative"):
            lines.append(f"- Broader alternative: {primary_pivot.get('broader_alternative')}")
        if primary_pivot.get("last_failure_reason"):
            lines.append(f"- Last pivot failure: {primary_pivot.get('last_failure_reason')}")
        if primary_pivot.get("role") == "exemplar" or primary_pivot.get("source_level") in ("case", "alert_aggregate"):
            lines.append(
                "- Do not require an exact match on this pivot unless raw evidence in this run upgrades it."
            )
        parts.append("\n".join(lines))

    active_pivots = [item for item in (ledger.get("active_pivots") or []) if isinstance(item, dict)]
    exhausted = [
        item for item in active_pivots
        if str(item.get("status") or "") == "exhausted" and item.get("field") and item.get("value")
    ]
    if exhausted:
        parts.append("Exhausted pivots:\n" + "\n".join(
            f"- {item.get('field')}={item.get('value')}" for item in exhausted[:6]
        ))

    adjacency = ledger.get("next_adjacent_evidence_path") or {}
    if isinstance(adjacency, dict) and any(adjacency.values()):
        lines = ["Next adjacent evidence path (the forward stage on the same asset/timeline):"]
        for key in ("entity", "time_direction", "window_hint", "representation_hint"):
            if adjacency.get(key):
                lines.append(f"- {key}: {adjacency[key]}")
        # Once the current stage is scoped, re-querying it rarely advances the objective.
        # This is what moves the window past a confirmed scan cluster toward execution.
        if (ledger.get("evidence_state") or "") in ("scoped_hits", "raw_events"):
            lines.append(
                "\nThe current stage is already scoped. Unless the last batch produced a NEW "
                "payload-bearing clue, your next tool batch should TARGET the adjacent path "
                "above rather than re-querying the same confirmed cluster."
            )
        parts.append("\n".join(lines))

    confirmed_findings = [
        item for item in (ledger.get("confirmed_findings") or [])
        if isinstance(item, dict) and str(item.get("summary") or "").strip()
    ]
    if confirmed_findings:
        parts.append(
            "Confirmed findings already established from raw evidence (do not replace "
            "these with '- None.' unless later raw evidence contradicts them):\n"
            + "\n".join(f"- {item.get('summary')}" for item in confirmed_findings[:8])
        )

    remaining_gaps = [
        str(item).strip() for item in (ledger.get("remaining_gaps") or []) if str(item).strip()
    ]
    if remaining_gaps:
        parts.append("Remaining gaps:\n" + "\n".join(f"- {item}" for item in remaining_gaps[:8]))

    board_context = ""
    queue_context = await _queue_context_for_state(state, tools)
    if state["agent_name"] == "investigation":
        get_board_fn = _tmap(tools).get("get_board")
        if get_board_fn:
            board_context = _format_board_context(await _call(get_board_fn, {}))
    live_context = (board_context + queue_context).strip()

    if not parts and not live_context:
        return ""
    out = "\n\n".join(parts)
    if live_context:
        out += ("\n\n" if out else "") + "# CONTEXT\n\n" + live_context
    return out


async def think(state: AgentState, config) -> dict:
    """Ask the model to reason about the current task and decide on tool calls or a report."""
    model = config["configurable"]["model"]
    tools = config["configurable"]["tools"]
    system_prompt = config["configurable"]["system_prompt"]
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "think", state)

    # ONE FLAT HISTORY PER TASK. Evidence accumulates across cycles and is cleared
    # only at `claim` (the task boundary). The anchor below is written once and never
    # replayed: re-sending the numbered startup checklist every cycle is what made
    # small models restart orientation, and that — not the evidence — is what the old
    # `messages: []` wipe was really protecting against. Instructions are transient
    # (`_cycle_steering`), evidence is durable.
    messages = _sanitize_history(list(state["messages"]))
    if not messages:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content="# USER\n" + _task_anchor(state)),
        ]

    # Per-task call cap: once this task has spent its tool budget, stop offering
    # tools so the model must synthesize what it has instead of burning the run's
    # remaining global budget on one task.
    # Enforce on the deterministic per-task counter ALONE — never on "is there a
    # ToolMessage in history?". The counter is snapshotted at claim, so it measures this
    # task only and cannot be fooled by how the history is assembled. (A ToolMessage-
    # presence guard silently defeated this cap back when the history was wiped each
    # cycle: session 8c1cd9ae spent 86 calls on one task. The history is retained now,
    # but the counter remains the correct thing to key on.)
    task_calls = state["tool_calls_made"] - state.get("task_call_floor", 0)
    task_capped = (
        state["agent_name"] == "investigation"
        and task_calls >= _MAX_TASK_TOOL_CALLS
    )

    model_tools = [] if task_capped else _model_tools_for_agent(
        state["agent_name"], tools, state.get("current_task")
    )
    bound = model.bind_tools(model_tools)

    ctx_tokens = state.get("ctx_tokens", 0)
    if _should_compact(ctx_tokens):
        emit(src, "note", f"context compaction triggered ({ctx_tokens:,} tokens)")
        messages = await _compact_history(messages, bound, state["agent_name"])
        ctx_tokens = 0  # reset; will be updated from next response

    # Per-cycle guidance rides on the model call but is NOT persisted, so instructions
    # never accumulate in the durable history. The old post-ToolMessage "write your
    # report now" nudge is gone: it was unreachable while `messages` was wiped every
    # cycle, and with a retained history it would fire on EVERY continuation and push
    # the model to conclude after its first tool batch.
    call_messages = messages
    if task_capped:
        emit(src, "note",
             f"per-task call cap reached ({task_calls}/{_MAX_TASK_TOOL_CALLS}) — "
             "forcing task wrap-up with findings so far")
        ledger = state.get("task_ledger") or {}
        preserved = [
            item for item in (ledger.get("confirmed_findings") or [])
            if isinstance(item, dict) and str(item.get("summary") or "").strip()
        ]
        preserved_text = ""
        if preserved:
            preserved_text = (
                "\n\nConfirmed findings already established from raw evidence; these MUST "
                "remain under ## Findings unless contradicted by later raw evidence:\n"
                + "\n".join(f"- {item.get('summary')}" for item in preserved[:8])
            )
        wrapup = HumanMessage(content=(
            f"You have reached this task's tool-call budget ({_MAX_TASK_TOOL_CALLS} "
            "calls). Do not request any more tools — none are available now. Write your "
            "complete response from the evidence already gathered, using the mandatory "
            "format:\n\n## Findings\n## Hypotheses\n## New Leads\n\n"
            "All three sections are required (use '- None.' if a section is empty). Put "
            "each confirmed indicator under ## Findings with its event ID. Record any "
            "still-open question under ## Hypotheses as [Open], and propose follow-up "
            "leads under ## New Leads (title, pivots, evidence, priority) so the work "
            "you could not finish here is picked up as a separate task."
            f"{preserved_text}"
        ))
        call_messages = call_messages + [wrapup]
    else:
        steering = await _cycle_steering(state, tools)
        if steering:
            call_messages = call_messages + [HumanMessage(content=steering)]

    response = await _invoke_bound_model(bound, call_messages, state["agent_name"])
    _sanitize_message(response)

    new_ctx = _track_input_tokens(response, src, ctx_tokens)

    # If the model produced nothing on the FIRST call for a task (empty messages
    # before this node ran), retry once with an explicit tool-use nudge. This
    # recovers model stalls where the initial response is completely silent.
    if (not (response.content or "").strip()
            and not getattr(response, "tool_calls", None)
            and not state.get("messages")):  # only on first task entry
        emit(src, "note", "silent response on task start — retrying with tool-use nudge")
        nudge_msgs = messages + [HumanMessage(content=(
            "Please make at least one tool call to begin this task. "
            "Use one of the available tools listed in your system prompt."
        ))]
        retry_resp = await _invoke_bound_model(bound, nudge_msgs, state["agent_name"])
        _sanitize_message(retry_resp)
        if (retry_resp.content or "").strip() or getattr(retry_resp, "tool_calls", None):
            response = retry_resp
            new_ctx = _track_input_tokens(retry_resp, src, new_ctx)

    # Evidence floor, `think` side. A reply with no tool calls IS a completion — it
    # routes straight to `assess`, never through `interpret`, so the floor in
    # `_route_interpret` cannot see it. Session 6b96293a lost three tasks this way:
    # they oriented (list_tasks / ls / search_feedback), wrote a report from earlier
    # tasks' evidence, and the board dropped every bullet as restated. Bounded to one
    # retry in-node so a model that insists on concluding cannot loop here.
    if (
        state["agent_name"] == "investigation"
        and not task_capped
        and not getattr(response, "tool_calls", None)
        and _count_evidence_queries(messages) == 0
        and state.get("tool_calls_made", 0) < (state.get("max_tool_calls") or 0)
    ):
        emit(src, "note",
             "evidence floor: concluding with no SIEM query this task — re-injecting")
        floor_msgs = messages + [response, HumanMessage(content=(
            "You are concluding this task without having run a single SIEM evidence query "
            "of your own — you only oriented (case/board/queue/filesystem) or reused what "
            "earlier tasks found. Reading prior findings is not investigating THIS task. "
            "Query the SIEM now for evidence specific to this task's objective: profile the "
            "window (`get_event_volume`), then `search`/`search_keyword`/`profile_field` on a "
            "concrete artifact named in the objective. If the honest answer is a confirmed "
            "negative, run the query that establishes it and cite the exact zero-result query."
        ))]
        retry = await _invoke_bound_model(bound, floor_msgs, state["agent_name"])
        _sanitize_message(retry)
        new_ctx = _track_input_tokens(retry, src, new_ctx)
        if getattr(retry, "tool_calls", None):
            response = retry
        else:
            emit(src, "note", "evidence floor: model declined to query — concluding anyway")

    text = (response.content or "").strip()
    if text:
        emit(src, "think", summarize_think(text), detail=text)
    return {
        "messages": messages + [response],
        "steps": state["steps"] + 1,
        "ctx_tokens": new_ctx,
    }


async def use_tools(state: AgentState, config) -> dict:
    tools = config["configurable"]["tools"]
    tmap = _tmap(_model_tools_for_agent(state["agent_name"], tools, state.get("current_task")))
    messages = list(state["messages"])
    last = messages[-1]
    new_calls = 0
    tool_runs: list[dict] = []
    tool_result_cache = dict(state.get("tool_result_cache") or {})

    src = src_label(state["agent_name"])
    _emit_node_entry(src, "use_tools", state)
    if await _cancel_requested(state["run_id"]):
        emit(src, "note", "cancel requested; no tool was executed")
        return {"status": "cancelled"}

    for tc in last.tool_calls:
        # Strip any leaked harmony/vllm control tokens from the tool name itself.
        # The content sanitizer cleans message bodies, but tool_calls[].name can
        # carry tokens like `search<|channel|>commentary` that break tool dispatch.
        raw_name = tc.get("name", "")
        clean_name = _HARMONY_TOKEN_RE.sub("", raw_name).strip()
        if clean_name != raw_name:
            tc = dict(tc)
            tc["name"] = clean_name
        args = tc.get("args", {})
        emit(
            src,
            "call",
            f"{tc['name']}({summarize_args(args)})",
            detail=json.dumps(args, indent=2, default=str),
        )
        tool = tmap.get(tc["name"])
        if tool is None:
            available = ", ".join(sorted(tmap))
            content = (
                f"Error: tool '{tc['name']}' does not exist and is not available. "
                f"Do not call it again. Available tools: {available}."
            )
            emit(src, "error", f"unknown tool '{tc['name']}'", detail=content)
        else:
            call_args = _expand_tilde_args(tc["args"])
            time_error = _time_window_guard(tc["name"], call_args, state, messages)
            if time_error:
                content = f"Error: {time_error}"
                emit(src, "error", f"{tc['name']} blocked: invalid time range", detail=content)
                messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))
                continue
            # AVFS `write` does not create parent directories; pre-create them so the
            # agent doesn't waste steps on an ENOENT failure → mkdir → retry cycle.
            if tc["name"] == "write":
                await _ensure_parent_dir(tmap, call_args.get("path"))
            cache_key = _tool_cache_key(tc["name"], call_args)
            cacheable = tc["name"] in _CACHEABLE_READ_TOOLS
            cached = cacheable and cache_key in tool_result_cache
            if cached:
                raw = tool_result_cache[cache_key]
                emit(src, "note", f"{tc['name']}: reused exact-argument cached result")
            else:
                # Log the FULL raw result to disk; feed only the capped copy to the model.
                raw = await _call(tool, call_args)
                if cacheable:
                    tool_result_cache[cache_key] = raw
            artifacts = []
            if state["agent_name"] == "investigation" and not cached and not _is_error_tool_result(raw):
                try:
                    artifacts = record_artifacts(
                        raw,
                        case_id=state["case_id"],
                        run_id=state["run_id"],
                        agent_name=state["agent_name"],
                    )
                    if artifacts:
                        emit(src, "note", f"findings board: {len(artifacts)} artifact(s) extracted")
                        await _auto_correlate_entities(artifacts, raw, state, tmap, src)
                        await _build_kill_chain(artifacts, raw, state, tmap, src)
                        await _enrich_artifacts_async(artifacts, state, src)
                except Exception as exc:
                    emit(src, "warning", "artifact extraction failed", detail=str(exc))
                try:
                    _memoize_query_and_schema(tc["name"], call_args, raw, state, src)
                except Exception as exc:
                    emit(src, "warning", "query memo failed", detail=str(exc))
            if tc["name"] == "write" and not _is_error_tool_result(raw):
                path = call_args.get("path")
                if isinstance(path, str):
                    async def call_tool(name: str, args: dict) -> str:
                        fn = tmap.get(name)
                        if fn is None:
                            return f"Error: tool '{name}' is not available"
                        return await _call(fn, args)

                    await update_memory_indexes(
                        call_tool=call_tool,
                        changed_path=path,
                        created_by=state["agent_name"],
                    )
            content = _cap_tool_result(raw)
            if not cached:
                new_calls += 1
            if _is_error_tool_result(raw):
                emit(src, "error", f"{tc['name']} failed: {summarize_result(tc['name'], raw)}", detail=raw)
            emit(src, "result", f"{tc['name']}: {summarize_result(tc['name'], raw)}", detail=raw)
            tool_runs.append({
                "name": tc["name"],
                "args": call_args,
                "raw": raw,
                "artifacts": artifacts,
            })
        messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))

    observation = build_observation(
        tool_runs,
        prior_observation=state.get("last_observation"),
        objective=((state.get("task_ledger") or {}).get("objective") or ""),
    )
    return {
        "messages": messages,
        "tool_calls_made": state["tool_calls_made"] + new_calls,
        "last_observation": observation,
        "tool_result_cache": tool_result_cache,
    }


# ── Post-tool enrichment (use_tools helpers): memoize, correlate, kill-chain, TI ──
def _memoize_query_and_schema(tool_name: str, args: dict, raw: str, state: dict, src: str) -> None:
    """Record a once-per-run board memo for over-broad query shapes and discovered
    schema fields (Phase 1 #13/#18), so later tasks don't re-pay the same broad-query
    tax or re-derive field names. Dedup keys make each shape/schema recorded once."""
    from ..analysis.query_memo import broad_query_memo, extract_schema_fields
    from .board import _record_board_entry

    memo = broad_query_memo(tool_name, args, raw)
    if memo:
        dedup_key, content = memo
        _record_board_entry(
            state, kind="query_memo", content=content, source="auto-memo",
            confidence="high", status="observed", dedup_key=dedup_key,
        )
        emit(src, "note", f"query memo: recorded broad query shape ({dedup_key})")

    fields = extract_schema_fields(tool_name, raw)
    if fields:
        idx = args.get("index_pattern") or "default"
        content = f"index `{idx}` fields ({len(fields)}): " + ", ".join(fields)
        _record_board_entry(
            state, kind="schema_fields", content=content[:1400], source="auto-memo",
            confidence="high", status="observed", dedup_key=f"schema:{idx}",
        )
        emit(src, "note", f"schema memo: recorded {len(fields)} field(s) for {idx}")


async def _auto_correlate_entities(artifacts: list, raw: str, state: dict, tmap: dict, src: str) -> None:
    """Correlate confirmed entities and assemble the connected incident graph on
    the findings board — the graph does this instead of relying on the model to call
    the tool (Fix 1; mirrors TI enrichment).

    Multi-hop (Fix #2): seed entities come from the tool result; when correlating one
    surfaces NEW high-value entities among its neighbors, those are correlated too —
    a bounded breadth-first walk (depth-limited, deduped per run, capped) that builds
    the linked attack graph rather than isolated 1-hop cards. The board injects the
    result into the next think prompt, so the model reasons over the graph.

    Emits a `metric` event per correlation for adoption/coverage telemetry (Fix 3).
    """
    corr_fn = tmap.get("correlate_entity")
    if corr_fn is None:
        return
    try:
        from collections import deque

        from ..analysis.correlation_leads import (
            MAX_CORRELATIONS, MAX_HOP_DEPTH, corr_dedup_key, derive_window,
            entities_from_neighbors, field_for, match_fields_for, select_targets,
            summarize_correlation,
        )
        from aci_board import store as board_store

        case_id, run_id, agent_name = state["case_id"], state["run_id"], state["agent_name"]
        board_store.init_db()
        existing = [
            e for e in board_store.list_entries(case_id, run_id, agent_name)
            if e.get("kind") == "correlation"
        ]
        covered = {(e.get("dedup_key") or "").lower() for e in existing}
        seeds = select_targets(
            artifacts, covered=covered, remaining_budget=MAX_CORRELATIONS - len(existing)
        )
        if not seeds:
            return

        vicinity = int(state.get("default_vicinity_window_hours") or 24)
        start, end = derive_window(raw, vicinity)

        # Breadth-first correlation walk. `visited` spans the run (board) + this walk
        # so an entity is correlated at most once; `remaining` enforces the run cap.
        visited = set(covered)
        remaining = MAX_CORRELATIONS - len(existing)
        queue: deque = deque((k, v, f, 0, None) for k, v, f in seeds)
        while queue and remaining > 0:
            kind, value, field, depth, via = queue.popleft()
            key = corr_dedup_key(kind, value)
            if key in visited:
                continue
            visited.add(key)

            args = {"field": field, "value": value, "match_fields": match_fields_for(kind)}
            if start and end:
                args["start_time"], args["end_time"] = start, end
            result_raw = await _call(corr_fn, args, _dbg=src)
            content, neighbor_count, has_cross = summarize_correlation(kind, value, result_raw, via=via)
            board_store.add_entry(
                case_id=case_id, run_id=run_id, agent_name=agent_name,
                kind="correlation", content=content, source="auto-correlation",
                confidence="high", status="observed", dedup_key=key,
            )
            remaining -= 1
            emit(src, "note",
                 f"auto-correlation[h{depth}]: {field}={value} → {neighbor_count} neighbor field(s)"
                 + (f" (via {via})" if via else "") + (" +cross_role" if has_cross else ""))
            emit(src, "metric",
                 f"correlation entity={kind}:{value} depth={depth} neighbors={neighbor_count} cross_role={int(has_cross)}")

            # Expand: enqueue newly-discovered neighbor entities for the next hop.
            if depth + 1 < MAX_HOP_DEPTH:
                for nk, nv in entities_from_neighbors(result_raw):
                    nkey = corr_dedup_key(nk, nv)
                    if nkey not in visited:
                        queue.append((nk, nv, field_for(nk), depth + 1, f"{kind}:{value}"))
    except Exception as exc:
        emit(src, "warning", "auto-correlation failed", detail=str(exc))


async def _build_kill_chain(artifacts: list, raw: str, state: dict, tmap: dict, src: str) -> None:
    """Build the MITRE ATT&CK kill-chain view for the case host and write it to the
    board (Fix #3). Runs once per run: triggered when a host artifact appears (real
    SIEM data is present) and no kill-chain entry exists yet. The board entry orders
    observed techniques along the kill chain and names the core phases with no
    evidence as gaps to investigate — the adversary-behavior view, graph-provided.
    """
    tech_fn = tmap.get("correlate_techniques")
    if tech_fn is None:
        return
    hosts = [a.value for a in artifacts if getattr(a, "kind", None) == "host" and a.value]
    if not hosts:
        return  # only attempt once we have a host to scope the kill chain to
    try:
        from ..analysis.correlation_leads import derive_window
        from ..analysis.kill_chain import drop_covered_specs, gap_lead_specs, summarize_kill_chain
        from aci_board import store as board_store

        case_id, run_id, agent_name = state["case_id"], state["run_id"], state["agent_name"]
        board_store.init_db()
        if any(e.get("kind") == "kill_chain"
               for e in board_store.list_entries(case_id, run_id, agent_name)):
            return  # already built this run

        vicinity = int(state.get("default_vicinity_window_hours") or 24)
        start, end = derive_window(raw, vicinity)
        args: dict = {"query": {"term": {"agent.name": hosts[0]}}}
        if start and end:
            args["start_time"], args["end_time"] = start, end
        result_raw = await _call(tech_fn, args, _dbg=src)
        content, observed, gaps = summarize_kill_chain(result_raw)
        # Only persist once techniques exist, so an early (pre-evidence) call doesn't
        # lock in an empty kill chain; a later host-bearing batch will populate it.
        if observed:
            board_store.add_entry(
                case_id=case_id, run_id=run_id, agent_name=agent_name,
                kind="kill_chain", content=content, source="auto-killchain",
                confidence="high", status="observed", dedup_key="killchain",
            )
            emit(src, "note", f"kill-chain: {len(observed)} tactic(s) observed; "
                 f"{len(gaps)} core gap(s)")
            emit(src, "metric",
                 f"kill_chain tactics={len(observed)} gaps={len(gaps)} host={hosts[0]}")

            # Fix #1: turn the gaps into concrete, prioritized, auto-queued leads
            # instead of relying on the model to convert the board GAP into a lead.
            if gaps:
                from aci_taskqueue import store as tq_store
                tq_store.init_db()
                specs = gap_lead_specs(
                    gaps, hosts[0],
                    window_hint=f"Window: ±{vicinity}h around the case/alert anchor timestamp.",
                    observed=observed,
                )
                # These go straight onto the queue, so they miss the lead validator
                # that dedups every other lead source. Without this, a forward-trace
                # lead duplicates a triage plan item AND outranks it (88 > 85/80/75),
                # so the duplicate runs first and the plan item finds nothing left.
                before = len(specs)
                specs = drop_covered_specs(
                    specs,
                    tq_store.list_tasks(case_id, run_id, agent_name) or [],
                )
                if before != len(specs):
                    emit(src, "note",
                         f"kill-chain gap leads: {before - len(specs)} already covered by "
                         "a queued task — skipped")
                for s in specs:
                    tq_store.create_task(
                        case_id=case_id, run_id=run_id, agent_name=agent_name,
                        title=s["title"], description=s["description"],
                        priority=s["priority"], origin="killchain_gap",
                    )
                if specs:
                    emit(src, "note", f"kill-chain gap leads: {len(specs)} task(s) queued")
                    emit(src, "metric", f"killchain_gap_leads={len(specs)}")
    except Exception as exc:
        emit(src, "warning", "kill-chain build failed", detail=str(exc))


async def _enrich_artifacts_async(artifacts: list, state: dict, src: str) -> None:
    """Enrich extracted artifacts against configured TI providers.

    Silently no-ops when no TI provider is configured (VT_API_KEY not set).
    Errors are caught and emitted as warnings so enrichment failures never
    interrupt the investigation graph.
    """
    try:
        from agent.ti.enricher import create_ti_leads, get_enricher, write_ti_results
    except Exception:
        return

    # get_enricher() reads ProviderConfig via the Django ORM, which raises
    # SynchronousOnlyOperation on the event loop (and is silently swallowed,
    # disabling TI). Build it on a worker thread so the ORM runs in sync context;
    # once cached, later calls are cheap and ORM-free.
    import asyncio

    enricher = await asyncio.to_thread(get_enricher)
    if enricher is None:
        return

    try:
        results = await enricher.enrich_artifacts_async(
            artifacts,
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
        )
    except Exception as exc:
        emit(src, "warning", "TI enrichment failed", detail=str(exc))
        return

    if not results:
        return

    try:
        flagged = write_ti_results(
            results,
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
        )
    except Exception as exc:
        emit(src, "warning", "TI board write failed", detail=str(exc))
        return

    verdicts = ", ".join(
        f"{r.artifact_kind} {r.artifact_value}={r.verdict}" for r in results
    )
    emit(src, "note", f"TI enrichment: {len(results)} result(s) — {verdicts}")

    if flagged:
        try:
            n = create_ti_leads(
                flagged,
                case_id=state["case_id"],
                run_id=state["run_id"],
                agent_name=state["agent_name"],
            )
            if n:
                emit(src, "note", f"TI enrichment: {n} investigation lead(s) created")
        except Exception as exc:
            emit(src, "warning", "TI lead creation failed", detail=str(exc))
