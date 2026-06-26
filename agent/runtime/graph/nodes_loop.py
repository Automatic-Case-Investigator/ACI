from __future__ import annotations

"""Graph nodes that drive task seeding, claiming, reasoning, and tool execution."""

import json

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ...agents.base import Handoff
from ...workspace.avfs_writer import update_memory_indexes
from ..analysis.artifacts import record_artifacts
from ..infra.logbus import emit, src_label, summarize_args, summarize_result, summarize_think, update_context_usage

from .board import _format_board_context
from .sanitize import _HARMONY_TOKEN_RE, _sanitize_history, _sanitize_message
from .state import AgentState
from .toolio import _call, _cancel_requested, _cap_tool_result, _compact_history, _emit_node_entry, _ensure_parent_dir, _expand_tilde_args, _extract_input_tokens, _has_pending_tasks, _invoke_bound_model, _is_error_tool_result, _list_tasks, _model_tools_for_agent, _parse_claimed_task, _reclaim_stale_tasks, _should_compact, _tmap



_QUEUE_CONTEXT_MAX_TASKS = 12
_QUEUE_CONTEXT_SNIPPET_CHARS = 120


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
        "and include title, pivots, evidence, and priority."
    )
    lines.append("---")
    return "\n".join(lines)


async def _queue_context_for_state(state: AgentState, tools: list) -> str:
    """Return a compact queue snapshot that helps investigation avoid duplicate leads."""
    if state["agent_name"] != "investigation":
        return ""
    task = state.get("current_task") or {}
    if "populate investigation queue" in (task.get("title") or "").lower():
        return ""
    tasks = await _list_tasks(tools, state["case_id"], state["run_id"], state["agent_name"])
    return _format_queue_context(tasks)



async def seed(state: AgentState, config) -> dict:
    """Populate the initial task queue for triage or investigation runs."""
    tools = config["configurable"]["tools"]
    create = _tmap(tools).get("create_task")
    agent_name = state["agent_name"]

    src = src_label(agent_name)
    _emit_node_entry(src, "seed", state)
    emit(src, "note", f"seed case={state['case_id']} run={state['run_id']}")
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)

    if agent_name == "triage":
        if create:
            description = (
                f"Analyst question: {state['question']}\n\n"
                "Complete the following triage steps and write a report. "
                "Use the tool names provided by the SOAR, SIEM, and memory MCP server guidance.\n"
                "1. Load the case record.\n"
                "2. Load the linked alert summary.\n"
                "3. Check known FP/TP patterns for this case's detection rule IDs.\n"
                "4. Check baselines for common behaviors.\n"
                "5. Check analyst corrections for these rule IDs.\n"
                "6. Load other alerts / events close to the current case / alert timestamp. "
                "After reading the case and linked alert summary, derive an absolute time "
                f"window around the alert timestamp using the configured default vicinity "
                f"window of ±{vicinity_hours} hours unless the task or evidence already gives "
                "an explicit absolute range, "
                "and query the SIEM with `search_keyword`, "
                "`search`, or `profile_field` for nearby events on the same host, user, "
                "source IP, and rule family. Summarize both matching events and zero-result "
                "queries in the report.\n\n"
                "After all steps, write the full triage report as the TEXT of your final "
                "message. The platform will generate the structured diagnosis verdict "
                "JSON block after your report. "
                "The platform records your text output — do not end with tool calls only."
            )
            result = await _call(create, {
                "case_id": state["case_id"],
                "run_id": state["run_id"],
                "agent_name": "triage",
                "title": f"Triage case {state['case_id']}",
                "description": description,
                "priority": 100,
            }, _dbg=src)
            if _is_error_tool_result(result):
                emit(src, "error", "seed: create_task FAILED", detail=str(result))
            else:
                emit(src, "note", "created triage task")

    else:
        # investigation: only seed a task if queue is empty
        already_seeded = await _has_pending_tasks(
            tools, state["case_id"], state["run_id"], state["agent_name"]
        )
        if not already_seeded and create:
            handoff = Handoff.from_dict(state.get("handoff"))
            has_triage = handoff is not None or "## Triage report" in state["question"]
            if has_triage:
                title = "Populate investigation queue from triage handoff"
                description = handoff.to_seed_text() if handoff else state["question"]
                description += (
                    f"\n\nWhen a triage plan item or open gap does not already specify an "
                    f"absolute time window, derive one using this run's configured default "
                    f"vicinity window of ±{vicinity_hours} hours around the anchor timestamp. "
                    "Do not silently substitute a narrower 24h or same-day range unless that "
                    "is the explicit evidence-backed window."
                )
                seed_tag = "created triage handoff task"
            else:
                title = f"Investigate case {state['case_id']}"
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
                seed_tag = "created fallback investigation task"
            result = await _call(create, {
                "case_id": state["case_id"],
                "run_id": state["run_id"],
                "agent_name": state["agent_name"],
                "title": title,
                "description": description,
                "priority": 100,
            }, _dbg=src)
            if _is_error_tool_result(result):
                emit(src, "error", "seed: create_task FAILED", detail=str(result))
            else:
                emit(src, "note", seed_tag)
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
    return {"current_task": task, "messages": []}


async def think(state: AgentState, config) -> dict:
    """Ask the model to reason about the current task and decide on tool calls or a report."""
    model = config["configurable"]["model"]
    tools = config["configurable"]["tools"]
    system_prompt = config["configurable"]["system_prompt"]
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "think", state)

    messages = _sanitize_history(list(state["messages"]))
    if not messages:
        task = state["current_task"]
        task_text = f"**Task:** {task['title']}\n\n{task.get('description') or ''}".strip()

        # Inject cross-task board and queue context for investigation tasks (not seed task)
        board_context = ""
        queue_context = await _queue_context_for_state(state, tools)
        if (state["agent_name"] == "investigation"
                and "populate investigation queue" not in (task.get("title") or "").lower()):
            get_board_fn = _tmap(tools).get("get_board")
            if get_board_fn:
                raw = await _call(get_board_fn, {})
                board_context = _format_board_context(raw)

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=task_text + board_context + queue_context),
        ]

    model_tools = _model_tools_for_agent(state["agent_name"], tools, state.get("current_task"))
    bound = model.bind_tools(model_tools)

    ctx_tokens = state.get("ctx_tokens", 0)
    if _should_compact(ctx_tokens):
        emit(src, "note", f"context compaction triggered ({ctx_tokens:,} tokens)")
        messages = await _compact_history(messages, bound, state["agent_name"])
        ctx_tokens = 0  # reset; will be updated from next response

    # After tool results, remind the model to write its findings as text.
    # Smaller models tend to return empty after executing tool calls; this
    # nudge is not saved to state so it does not accumulate in history.
    call_messages = messages
    if call_messages and isinstance(call_messages[-1], ToolMessage):
        queue_context = await _queue_context_for_state(state, tools)
        call_messages = call_messages + [HumanMessage(content=(
            "Tool calls complete. Write your response now using the mandatory "
            "structured format:\n\n"
            "## Confirmed Facts\n"
            "## Findings\n"
            "## Hypotheses\n"
            "## New Leads\n\n"
            "All four sections are required (use '- None.' if a section is empty). "
            "For each proposed lead use this exact structure: title, pivots, evidence, "
            "priority. The platform validates and queues approved leads; do not call "
            "`create_task` for follow-up work. Only propose leads that are evidence-backed "
            "and not already covered in the current queue."
            f"{queue_context}"
        ))]

    response = await _invoke_bound_model(bound, call_messages, state["agent_name"])
    _sanitize_message(response)

    new_ctx = _extract_input_tokens(response) or ctx_tokens
    if new_ctx:
        update_context_usage(new_ctx, src)

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
            new_ctx = _extract_input_tokens(retry_resp) or new_ctx

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
            # AVFS `write` does not create parent directories; pre-create them so the
            # agent doesn't waste steps on an ENOENT failure → mkdir → retry cycle.
            if tc["name"] == "write":
                await _ensure_parent_dir(tmap, call_args.get("path"))
            # Log the FULL raw result to disk; feed only the capped copy to the model.
            raw = await _call(tool, call_args)
            if state["agent_name"] == "investigation" and not _is_error_tool_result(raw):
                try:
                    artifacts = record_artifacts(
                        raw,
                        case_id=state["case_id"],
                        run_id=state["run_id"],
                        agent_name=state["agent_name"],
                    )
                    if artifacts:
                        emit(src, "note", f"findings board: {len(artifacts)} artifact(s) extracted")
                        await _enrich_artifacts_async(artifacts, state, src)
                except Exception as exc:
                    emit(src, "warning", "artifact extraction failed", detail=str(exc))
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
            new_calls += 1
            if _is_error_tool_result(raw):
                emit(src, "error", f"{tc['name']} failed: {summarize_result(tc['name'], raw)}", detail=raw)
            emit(src, "result", f"{tc['name']}: {summarize_result(tc['name'], raw)}", detail=raw)
        messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))

    return {
        "messages": messages,
        "tool_calls_made": state["tool_calls_made"] + new_calls,
    }


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
