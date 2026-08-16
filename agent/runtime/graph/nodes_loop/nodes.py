from __future__ import annotations

"""The per-task loop nodes: seed -> claim -> think -> use_tools."""

from ..state import AgentState
from ....agents.base import Handoff
from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage
from langchain_core.messages import ToolMessage
from ..sanitize import _HARMONY_TOKEN_RE
from ..toolio import _call
from ..toolio import _cancel_requested
from ..toolio import _cap_tool_result
from ..toolio import _compact_history
from ..coverage import _count_evidence_queries
from ..interpretation import _default_ledger
from ..toolio import _emit_node_entry
from ..toolio import _ensure_parent_dir
from ..toolio import _ensure_workspace_dirs
from ..toolio import _expand_tilde_args
from ..board import _format_board_context
from ..toolio import _has_pending_tasks
from ..toolio import _invoke_bound_model
from ..toolio import _is_error_tool_result
from ..toolio import _model_tools_for_agent
from ..toolio import _parse_claimed_task
from ..toolio import _reclaim_stale_tasks
from ..sanitize import _sanitize_history
from ..sanitize import _sanitize_message
from ..toolio import _should_compact
from ..toolio import _tmap
from ..toolio import _track_input_tokens
from ..observation import build_observation
from ...infra.logbus import emit
import json
from ...analysis.artifacts import record_artifacts
from ...engine.seeder_runner import run_seeder
from ...infra.logbus import src_label
from ...infra.logbus import summarize_args
from ...infra.logbus import summarize_result
from ..coverage import _EVIDENCE_TOOLS
from ..parsing import _missing_triage_sections
from ...analysis.intent import generate_public_intent
from ...infra.logbus import summarize_think
from ...infra.logbus import summarize_think
from ....workspace.avfs_writer import update_memory_indexes

from ._const import _CACHEABLE_READ_TOOLS, _MAX_TASK_TOOL_CALLS, _tool_cache_key
from .context import _queue_context_for_state, _time_window_guard
from .enrichment import _auto_correlate_entities, _build_kill_chain, _enrich_artifacts_async, _memoize_query_and_schema


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
        # Triage runs the flat loop (`triage_think`, below), which anchors on the
        # analyst's question directly and never claims from the queue, so there is no
        # task to seed. The objective text comes from `build_triage_objective`.
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
                    result = await _call(
                        create,
                        {
                            "title": "Populate investigation queue from triage handoff",
                            "description": description,
                            "priority": 100,
                        },
                        _dbg=src,
                    )
                    if _is_error_tool_result(result):
                        emit(
                            src, "error", "seed: create_task FAILED", detail=str(result)
                        )
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
                    result = await _call(
                        create,
                        {
                            "title": f"Investigate {state['case_id']}",
                            "description": description,
                            "priority": 100,
                        },
                        _dbg=src,
                    )
                    if _is_error_tool_result(result):
                        emit(
                            src, "error", "seed: create_task FAILED", detail=str(result)
                        )
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
            emit(
                src,
                "note",
                f"recovered {recovered} stale claimed task(s) — retrying claim",
            )
            task = _parse_claimed_task(await _call(claim_fn, args, _dbg=src))
    if task:
        emit(
            src,
            "task",
            f"[P{task.get('priority', '?')}] {task.get('title', '?')}",
            detail=json.dumps(task, indent=2, default=str),
        )
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
    text = (
        f"**Task:** {task.get('title', '')}\n\n{task.get('description') or ''}".strip()
    )
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
        str(item).strip()
        for item in (ledger.get("forbidden_repeats") or [])
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
    if (
        isinstance(primary_pivot, dict)
        and primary_pivot.get("field")
        and primary_pivot.get("value")
    ):
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
            lines.append(
                f"- Broader alternative: {primary_pivot.get('broader_alternative')}"
            )
        if primary_pivot.get("last_failure_reason"):
            lines.append(
                f"- Last pivot failure: {primary_pivot.get('last_failure_reason')}"
            )
        if primary_pivot.get("role") == "exemplar" or primary_pivot.get(
            "source_level"
        ) in ("case", "alert_aggregate"):
            lines.append(
                "- Do not require an exact match on this pivot unless raw evidence in this run upgrades it."
            )
        parts.append("\n".join(lines))

    active_pivots = [
        item for item in (ledger.get("active_pivots") or []) if isinstance(item, dict)
    ]
    exhausted = [
        item
        for item in active_pivots
        if str(item.get("status") or "") == "exhausted"
        and item.get("field")
        and item.get("value")
    ]
    if exhausted:
        parts.append(
            "Exhausted pivots:\n"
            + "\n".join(
                f"- {item.get('field')}={item.get('value')}" for item in exhausted[:6]
            )
        )

    adjacency = ledger.get("next_adjacent_evidence_path") or {}
    if isinstance(adjacency, dict) and any(adjacency.values()):
        lines = [
            "Next adjacent evidence path (the forward stage on the same asset/timeline):"
        ]
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
        item
        for item in (ledger.get("confirmed_findings") or [])
        if isinstance(item, dict) and str(item.get("summary") or "").strip()
    ]
    if confirmed_findings:
        parts.append(
            "Confirmed findings already established from raw evidence (do not replace "
            "these with '- None.' unless later raw evidence contradicts them):\n"
            + "\n".join(f"- {item.get('summary')}" for item in confirmed_findings[:8])
        )

    remaining_gaps = [
        str(item).strip()
        for item in (ledger.get("remaining_gaps") or [])
        if str(item).strip()
    ]
    if remaining_gaps:
        parts.append(
            "Remaining gaps:\n" + "\n".join(f"- {item}" for item in remaining_gaps[:8])
        )

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
        state["agent_name"] == "investigation" and task_calls >= _MAX_TASK_TOOL_CALLS
    )

    model_tools = (
        []
        if task_capped
        else _model_tools_for_agent(
            state["agent_name"], tools, state.get("current_task")
        )
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
        emit(
            src,
            "note",
            f"per-task call cap reached ({task_calls}/{_MAX_TASK_TOOL_CALLS}) — "
            "forcing task wrap-up with findings so far",
        )
        ledger = state.get("task_ledger") or {}
        preserved = [
            item
            for item in (ledger.get("confirmed_findings") or [])
            if isinstance(item, dict) and str(item.get("summary") or "").strip()
        ]
        preserved_text = ""
        if preserved:
            preserved_text = (
                "\n\nConfirmed findings already established from raw evidence; these MUST "
                "remain under ## Findings unless contradicted by later raw evidence:\n"
                + "\n".join(f"- {item.get('summary')}" for item in preserved[:8])
            )
        wrapup = HumanMessage(
            content=(
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
            )
        )
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
    if (
        not (response.content or "").strip()
        and not getattr(response, "tool_calls", None)
        and not state.get("messages")
    ):  # only on first task entry
        emit(
            src, "note", "silent response on task start — retrying with tool-use nudge"
        )
        nudge_msgs = messages + [
            HumanMessage(
                content=(
                    "Please make at least one tool call to begin this task. "
                    "Use one of the available tools listed in your system prompt."
                )
            )
        ]
        retry_resp = await _invoke_bound_model(bound, nudge_msgs, state["agent_name"])
        _sanitize_message(retry_resp)
        if (retry_resp.content or "").strip() or getattr(
            retry_resp, "tool_calls", None
        ):
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
        emit(
            src,
            "note",
            "evidence floor: concluding with no SIEM query this task — re-injecting",
        )
        floor_msgs = messages + [
            response,
            HumanMessage(
                content=(
                    "You are concluding this task without having run a single SIEM evidence query "
                    "of your own — you only oriented (case/board/queue/filesystem) or reused what "
                    "earlier tasks found. Reading prior findings is not investigating THIS task. "
                    "Query the SIEM now for evidence specific to this task's objective: profile the "
                    "window (`get_event_volume`), then `search`/`search_keyword`/`profile_field` on a "
                    "concrete artifact named in the objective. If the honest answer is a confirmed "
                    "negative, run the query that establishes it and cite the exact zero-result query."
                )
            ),
        ]
        retry = await _invoke_bound_model(bound, floor_msgs, state["agent_name"])
        _sanitize_message(retry)
        new_ctx = _track_input_tokens(retry, src, new_ctx)
        if getattr(retry, "tool_calls", None):
            response = retry
        else:
            emit(
                src,
                "note",
                "evidence floor: model declined to query — concluding anyway",
            )

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
    tmap = _tmap(
        _model_tools_for_agent(state["agent_name"], tools, state.get("current_task"))
    )
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
                emit(
                    src,
                    "error",
                    f"{tc['name']} blocked: invalid time range",
                    detail=content,
                )
                messages.append(
                    ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"])
                )
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
            if (
                state["agent_name"] == "investigation"
                and not cached
                and not _is_error_tool_result(raw)
            ):
                try:
                    artifacts = record_artifacts(
                        raw,
                        case_id=state["case_id"],
                        run_id=state["run_id"],
                        agent_name=state["agent_name"],
                    )
                    if artifacts:
                        emit(
                            src,
                            "note",
                            f"findings board: {len(artifacts)} artifact(s) extracted",
                        )
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
                emit(
                    src,
                    "error",
                    f"{tc['name']} failed: {summarize_result(tc['name'], raw)}",
                    detail=raw,
                )
            emit(
                src,
                "result",
                f"{tc['name']}: {summarize_result(tc['name'], raw)}",
                detail=raw,
            )
            tool_runs.append(
                {
                    "name": tc["name"],
                    "args": call_args,
                    "raw": raw,
                    "artifacts": artifacts,
                }
            )
        messages.append(
            ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"])
        )

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


# ── Triage's flat loop: triage_think replaces think/interpret for the triage agent ──
# Triage has no task queue and no interpret node -- it anchors on the alert and
# writes its report in one loop, so its think node lives here beside the others
# rather than in a module of its own.

# Minimum distinct evidence-tool calls before a final answer is accepted. The
# interpret node used to enforce depth by judgement; with it gone this is the
# deterministic backstop against a report written from the alert record alone.
_MIN_EVIDENCE_CALLS = 3

# Bounded in-node corrections. A deficient final answer (too little evidence, or
# a malformed report) is nudged rather than routed, so the graph stays a simple
# two-state loop: this node either emits tool calls or a finished report.
_MAX_CORRECTIONS = 2


def build_triage_objective(state: AgentState) -> str:
    """The anchor message: the analyst's literal question plus how to answer it.

    Sent ONCE, as message[1], and never replayed — mirroring the orchestrator,
    whose message[1] is the analyst's question. The methodology lives here rather
    than in a per-cycle nudge so it cannot be re-read as a checklist to restart.
    """
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
    question = (state.get("question") or "").strip()
    entity = (state.get("source_entity_id") or state.get("case_id") or "").strip()

    return (
        "# USER\n"
        f"The analyst asked: {question}\n\n"
        f"Entity under triage: {entity or '(resolve it from the question)'}\n\n"
        "Answer THAT question, grounded in raw evidence you retrieved. Everything "
        "below is how to get there — it is not a checklist to tick off.\n\n"
        "Ground the entity first. Let the analyst's own wording (case / alert / "
        "event) choose the first lookup — do not guess from the id's shape. If they "
        "called it an alert, load the actual ALERT record and read its raw fields; "
        "if that lookup fails, try the case lookup, then a SIEM search on the "
        "identifier itself.\n\n"
        "Then run the analyst loop on the concrete pivots (host, user, source IP, "
        "rule family):\n"
        "- PROFILE the discriminating fields (`profile_field`) to see what values "
        "actually exist and what deviates from the baseline, before you filter on them.\n"
        "- RETRIEVE AND READ the specific raw events behind the hits (`get_event` on "
        "the ids a `search`/`search_keyword` returns) — open the actual event and "
        "read its fields (command, path, status, user, decoded payload). A hit count "
        "is not evidence, and neither is an aggregate: `correlate_entity` tells you "
        "WHICH events matter, then you must go read them.\n"
        "- CORRELATE the key entities (`correlate_entity`) to follow the chain the "
        "alert sits in — the same user/host/IP across roles and adjacent time.\n\n"
        "When a query names an artifact you have not read — an event id, a command, "
        "a path, an encoded payload — reading it is the next step, not a follow-up "
        "for someone else. The decisive evidence is usually DOWNSTREAM of the alert "
        "that fired, not inside it.\n\n"
        "Let historical context INFORM this loop, not replace it: known FP/TP "
        "patterns, prior analyst feedback, and entity baselines shape your "
        "disposition, but they are context, not evidence — never conclude from them "
        "without reading the raw events.\n\n"
        "Derive an absolute time window around the case `date` field or alert "
        f"timestamp using the configured default vicinity window of ±{vicinity_hours} "
        "hours unless the evidence already gives an explicit absolute range; start "
        "tighter and widen toward that bound only if empty.\n\n"
        "You are done when the analyst's question is ANSWERED from raw evidence — "
        "not when a fixed number of steps has run, and not when you have merely "
        "gathered context around the alert. Triage is bounded: once the question is "
        "answered, or you have capably established the evidence is not there, stop "
        "and write the report. Carry genuinely unresolved adjacent threads into the "
        "investigation plan rather than chasing them here.\n\n"
        + _report_format_instruction(vicinity_hours)
    )


def _report_format_instruction(vicinity_hours: int) -> str:
    """The three-section handoff contract. Also reused as the correction nudge."""
    return (
        "When you are ready, write the full triage report as the TEXT of your reply, "
        "using the mandatory structured format:\n\n"
        "## Triage Summary\n"
        "## Key Evidence\n"
        "## Investigation Plan\n\n"
        "All three sections are required. In ## Investigation Plan, every item must "
        "include an explicit absolute time window. If an item does not have a "
        "narrower evidence-derived range, derive it from the configured default "
        f"vicinity window of ±{vicinity_hours} hours around the anchor timestamp. Do "
        f"not use ±24 hours unless this run's configured value is {vicinity_hours}. "
        "If an item intentionally uses a narrower range, state why. Do not paste raw "
        "JSON objects, entity dumps, or tool payloads as the report — explain what "
        "the evidence means in prose, then list concrete evidence as bullets. The "
        "platform generates the structured verdict JSON after your report; do not "
        "end your turn with tool calls only."
    )


def _evidence_call_count(messages: list) -> int:
    """Evidence-tool calls made so far, counted from the flat history.

    Deterministic and history-derived rather than a state counter, because the
    history IS the durable record in a flat loop.
    """
    seen = 0
    for msg in messages:
        for call in getattr(msg, "tool_calls", None) or []:
            if call.get("name") in _EVIDENCE_TOOLS:
                seen += 1
    return seen


def _deficiency(text: str, messages: list) -> str:
    """Why this final answer is not acceptable yet, or '' if it is.

    Evidence depth is checked BEFORE report shape: a well-formatted report written
    from no evidence is the failure that matters, and telling the model to fix its
    headings first would let it re-submit the same ungrounded content.
    """
    evidence_calls = _evidence_call_count(messages)
    if evidence_calls < _MIN_EVIDENCE_CALLS:
        return (
            f"You have made only {evidence_calls} evidence "
            f"{'query' if evidence_calls == 1 else 'queries'} so far, which is not "
            "enough to ground a triage disposition. Do not write the report yet. Go read the "
            "raw events behind this alert — use `search`/`search_keyword` to locate "
            "them and `get_event` to open the specific ids, and follow the chain "
            "downstream of the alert. Make the tool calls now."
        )
    missing = _missing_triage_sections(text)
    if missing:
        return (
            "Your report is missing or has an empty "
            f"{', '.join(missing)} section. Rewrite the COMPLETE report from the "
            "evidence already in this conversation, keeping every section non-empty."
        )
    return ""


async def triage_think(state: AgentState, config) -> dict:
    """One cycle of the flat triage loop: narrate intent, then act or conclude."""
    tools = config["configurable"]["tools"]
    model = config["configurable"]["model"]
    system_prompt = config["configurable"].get("system_prompt", "")
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "think", state)

    messages = _sanitize_history(list(state.get("messages") or []))
    if not messages:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=build_triage_objective(state)),
        ]

    model_tools = _model_tools_for_agent(state["agent_name"], tools, None)
    bound = model.bind_tools(model_tools)
    ctx_tokens = state.get("ctx_tokens", 0)

    if _should_compact(ctx_tokens):
        emit(src, "note", f"context compaction triggered ({ctx_tokens:,} tokens)")
        messages = await _compact_history(messages, bound, state["agent_name"])
        ctx_tokens = 0

    # Per-cycle public intent, generated from the FULL history — the orchestrator's
    # planning step. Re-reading everything retrieved so far is what lets the model
    # connect evidence across cycles instead of reacting to the latest batch.
    intent = await generate_public_intent(
        model,
        messages,
        source=src,
        sequence=state["steps"] + 1,
        task_title=(state.get("question") or "").strip(),
        available_tools=[getattr(t, "name", "") for t in model_tools],
    )
    if intent.text:
        messages = messages + [
            HumanMessage(
                content=(
                    "[Public intent already shown to the analyst]\n"
                    f"{intent.text}\n\n"
                    "Perform that action now. Make the tool calls needed to answer the "
                    "analyst's question, or write your triage report as text if the "
                    "evidence you hold already answers it."
                )
            )
        ]

    response = await _invoke_bound_model(bound, messages, state["agent_name"])
    _sanitize_message(response)
    ctx_tokens = _track_input_tokens(response, src, ctx_tokens)
    messages = messages + [response]

    # Tool calls: hand off to `use_tools`, which appends results to this same history.
    if getattr(response, "tool_calls", None):
        text = (response.content or "").strip()
        if text:
            emit(src, "think", summarize_think(text), detail=text)
        return {
            "messages": messages,
            "steps": state["steps"] + 1,
            "ctx_tokens": ctx_tokens,
        }

    # No tool calls: the model is concluding. Accept only a grounded, well-formed
    # report; otherwise correct it in-node so routing stays a simple two-state loop.
    text = (response.content or "").strip()
    for _ in range(_MAX_CORRECTIONS):
        budget_left = (
            state["steps"] + 1 < state["max_steps"]
            and state["tool_calls_made"] < state["max_tool_calls"]
        )
        problem = _deficiency(text, messages) if budget_left else ""
        if not problem:
            break
        emit(src, "note", f"triage self-correction: {problem.split('.')[0][:110]}")
        messages = messages + [HumanMessage(content=problem)]
        response = await _invoke_bound_model(bound, messages, state["agent_name"])
        _sanitize_message(response)
        ctx_tokens = _track_input_tokens(response, src, ctx_tokens)
        messages = messages + [response]
        if getattr(response, "tool_calls", None):
            # The correction sent it back for evidence — resume the normal loop.
            return {
                "messages": messages,
                "steps": state["steps"] + 1,
                "ctx_tokens": ctx_tokens,
            }
        text = (response.content or "").strip()

    # Last resort — the shape guard `assess` used to own. Corrections are advisory
    # (the model may ignore them); this is not. Without it a raw blob reaches the
    # verdict contract as the handoff, which is what the ledger loop protected against.
    missing = _missing_triage_sections(text)
    if missing:
        forced = await _force_report_shape(model, messages, state, src, missing)
        # Only take the rewrite if it is actually better shaped — a still-broken
        # model must not be allowed to replace one malformed answer with another.
        if forced and len(_missing_triage_sections(forced)) < len(missing):
            text = forced

    if text:
        emit(src, "think", summarize_think(text), detail=text)
    return {
        "messages": messages,
        "steps": state["steps"] + 1,
        "ctx_tokens": ctx_tokens,
        "final_answer": text,
    }


async def _force_report_shape(
    model,
    messages: list,
    state: AgentState,
    src: str,
    missing: list[str],
) -> str:
    """Tool-free synthesis of a durable three-section report from the conversation.

    Keeps the wording the `assess` shape guard used, so the repair instruction the
    model sees for a malformed triage handoff is unchanged by the move to the flat loop.
    """
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
    emit(
        src,
        "note",
        f"triage report malformed, missing {', '.join(missing)} — requesting text synthesis",
    )
    try:
        text_only = model.bind_tools([])
        prompt = HumanMessage(
            content=(
                "Your previous reply was not a valid triage handoff report. "
                "Rewrite the triage handoff as a complete text report now. Do not make "
                "any further tool calls, and do not paste raw JSON or entity dumps as the "
                "report body — ground it only in the tool results already in this "
                "conversation.\n\n" + _report_format_instruction(vicinity_hours)
            )
        )
        resp = await _invoke_bound_model(
            text_only,
            _sanitize_history(messages + [prompt]),
            state["agent_name"],
        )
        _sanitize_message(resp)
        return (resp.content or "").strip()
    except Exception as exc:  # noqa: BLE001 - never fail the run on the safety net
        emit(src, "error", f"triage report synthesis failed: {exc}")
        return ""
