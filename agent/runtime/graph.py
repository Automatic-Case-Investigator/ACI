"""LangGraph agent graph.

Queue-driven loop (shared by triage and investigation):
  seed -> claim --(task)--> think <-> use_tools -> assess -> claim
                 (empty) --> finish -> END

Seed behaviour differs by agent:
- triage: creates one initial "triage" task that produces a triage report and
  proposed investigation plan only.
- investigation: creates the initial investigation task from the orchestrator
  handoff when its queue is empty; that task seeds any follow-up queue work.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

from ..agents.base import Handoff
from ..workspace.avfs_writer import update_memory_indexes, write_file
from .avfs import reports_dir, findings_dir, case_dir, home_dir
from .artifacts import record_artifacts
from .logbus import emit, src_label, summarize_args, summarize_result, summarize_think
from .logbus import update_context_usage
from .intent import generate_public_intent
from .streaming import invoke_streaming

log = logging.getLogger(__name__)


class AgentState(TypedDict):
    run_id: str
    case_id: str
    agent_name: str
    question: str
    handoff: Optional[dict]
    current_task: Optional[dict]
    messages: list
    steps: int
    tool_calls_made: int
    max_steps: int
    max_tool_calls: int
    status: str
    final_answer: str
    ctx_tokens: int  # input tokens from the most recent model call
    current_intent: str
    intent_sequence: int
    model_calls_made: int


def _tmap(tools: list) -> dict:
    return {t.name: t for t in tools}


_SEED_TASK_TITLE = "populate investigation queue"

# claim_next is graph-managed: the `claim` node owns task claiming.
# Giving it to the model causes it to mark tasks `claimed` before they run,
# making the queue appear empty to the graph's claim node.
_GRAPH_MANAGED_TOOLS = frozenset({"claim_next"})

# During the seed task the model's ONLY job is to call create_task.
# Restricting it to these two tools removes all distractors (board, AVFS, SIEM)
# that cause small models to pick the wrong tool or stall.
_SEED_TASK_TOOLS = frozenset({"create_task", "list_tasks", "complete_task"})


def _model_tools_for_agent(
    agent_name: str, tools: list, current_task: dict | None = None
) -> list:
    excluded = set(_GRAPH_MANAGED_TOOLS)
    if agent_name == "triage":
        excluded.add("create_task")
        return [t for t in tools if getattr(t, "name", "") not in excluded]
    # Restrict to task-queue tools only during the seed task so the model cannot
    # be distracted by board / AVFS / SIEM tools when its sole job is create_task.
    if (current_task and agent_name == "investigation"
            and _SEED_TASK_TITLE in (current_task.get("title") or "").lower()):
        return [t for t in tools if getattr(t, "name", "") in _SEED_TASK_TOOLS]
    return [t for t in tools if getattr(t, "name", "") not in excluded]


# gpt-oss emits the "harmony" format; vllm's parser sometimes leaks raw control
# tokens (e.g. <|channel|>, <|end|>, <|start|>) into the assistant message. When
# that text is echoed back in history, vllm fails to re-parse it ("unexpected
# tokens remaining in message header"). Strip these before storing any message.
_HARMONY_TOKEN_RE = re.compile(r"<\|[^|>]*\|>")
_LEAKED_TOOL_HEADER_RE = re.compile(r"(?im)^\s*to=functions\.[^\n]*$")
_LEAKED_ROLE_LINE_RE = re.compile(r"(?im)^\s*assistant\s*$")


def _strip_harmony(text):
    if not isinstance(text, str):
        return text
    cleaned = _HARMONY_TOKEN_RE.sub("", text)
    cleaned = _LEAKED_TOOL_HEADER_RE.sub("", cleaned)
    cleaned = _LEAKED_ROLE_LINE_RE.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _sanitize_message(msg):
    """Remove harmony control tokens from an assistant message before it re-enters
    the conversation history."""
    if isinstance(getattr(msg, "content", None), str):
        msg.content = _strip_harmony(msg.content)
    ak = getattr(msg, "additional_kwargs", None)
    if isinstance(ak, dict) and isinstance(ak.get("reasoning_content"), str):
        ak["reasoning_content"] = _strip_harmony(ak["reasoning_content"])
    return msg


def _sanitize_history(messages: list, *, aggressive: bool = False) -> list:
    """Sanitize model history before an LLM call.

    aggressive=True additionally drops assistant chatter that still looks like a
    leaked tool header fragment after cleanup.
    """
    sanitized: list = []
    for msg in messages:
        _sanitize_message(msg)
        content = getattr(msg, "content", None)
        tool_calls = getattr(msg, "tool_calls", None)
        if aggressive and isinstance(content, str) and not tool_calls:
            if "to=functions." in content or "<|start|>" in content or "<|end|>" in content:
                continue
        sanitized.append(msg)
    return sanitized


async def _invoke_bound_model(bound, messages: list, agent_name: str):
    """Invoke the chat model; on known vLLM header parsing failure, retry once
    with aggressive history sanitation."""
    source = src_label(agent_name)
    try:
        return await invoke_streaming(bound, messages, agent_name, source)
    except Exception as exc:
        if "unexpected tokens remaining in message header" not in str(exc):
            raise
        repaired = _sanitize_history(messages, aggressive=True)
        log.warning(
            "[%s] think -- retrying after sanitizing leaked control-header text",
            agent_name,
        )
        emit(
            src_label(agent_name),
            "warning",
            "retrying model call after sanitizing leaked control-header text",
            detail=str(exc),
        )
        try:
            return await invoke_streaming(bound, repaired, agent_name, source)
        except Exception as exc2:
            if "unexpected tokens remaining in message header" not in str(exc2):
                raise
            from langchain_core.messages import AIMessage
            log.warning(
                "[%s] think -- double harmony-token failure, returning empty response",
                agent_name,
            )
            emit(src_label(agent_name), "warning", "double harmony-token failure — empty response used")
            return AIMessage(content="")


def _normalize(result) -> str:
    """Flatten an MCP tool result to plain text.

    langchain-mcp-adapters returns a list of content blocks, e.g.
    [{"type": "text", "text": "<json>", "id": "lc_..."}]. We extract and
    join the text payloads so callers see the inner JSON/string directly.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        texts: list[str] = []
        for block in result:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif isinstance(block, str):
                texts.append(block)
            else:
                text_attr = getattr(block, "text", None)
                if text_attr is not None:
                    texts.append(text_attr)
        if texts:
            return "\n".join(texts)
    return json.dumps(result, default=str)


def _extract_input_tokens(response) -> int:
    """Pull input token count from a LangChain AIMessage (OpenAI-compatible)."""
    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        return usage.get("input_tokens", 0)
    meta = getattr(response, "response_metadata", None)
    if isinstance(meta, dict):
        tu = meta.get("token_usage") or meta.get("usage") or {}
        return tu.get("prompt_tokens", 0)
    return 0


def _should_compact(ctx_tokens: int) -> bool:
    if not ctx_tokens:
        return False
    try:
        from django.conf import settings
        limit = getattr(settings, "LLM_CONTEXT_LENGTH", 131072)
    except Exception:
        limit = 131072
    return ctx_tokens >= int(limit * 0.8)


async def _compact_history(messages: list, bound, agent_name: str) -> list:
    """Summarise old conversation turns to reduce context size.

    Keeps the last 4 conversation messages verbatim; everything before that is
    replaced by a single summary HumanMessage. Returns the original list on any
    failure so the caller can continue normally.
    """
    sys_msgs = [m for m in messages if isinstance(m, SystemMessage)]
    conv_msgs = [m for m in messages if not isinstance(m, SystemMessage)]
    if len(conv_msgs) < 6:
        return messages

    keep = 4
    to_summarize = conv_msgs[:-keep]
    recent = conv_msgs[-keep:]

    try:
        resp = await bound.ainvoke([
            *sys_msgs,
            *to_summarize,
            HumanMessage(content=(
                "Concisely summarise the above conversation. Preserve: case IDs, "
                "host names, IPs, key findings, tool results still relevant, and "
                "any context established so far. This replaces the prior history."
            )),
        ])
        _sanitize_message(resp)
        summary = (resp.content or "").strip()
    except Exception:
        return messages

    if not summary:
        return messages

    return [*sys_msgs, HumanMessage(content=f"[Prior context summary]\n\n{summary}"), *recent]


async def _call(tool, args: dict) -> str:
    try:
        result = await tool.ainvoke(args)
        return _normalize(result)
    except Exception as exc:
        return f"Error: {exc}"


async def _list_tasks(tools: list, case_id: str, run_id: str, agent_name: str) -> list:
    """Return all tasks for the current run (empty list on failure)."""
    list_fn = _tmap(tools).get("list_tasks")
    if list_fn is None:
        return []
    raw = await _call(list_fn, {"case_id": case_id, "run_id": run_id, "agent_name": agent_name})
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        tasks = data if isinstance(data, list) else data.get("tasks", [])
        return tasks if isinstance(tasks, list) else []
    except Exception:
        return []


async def _has_pending_tasks(tools: list, case_id: str, run_id: str, agent_name: str) -> bool:
    tasks = await _list_tasks(tools, case_id, run_id, agent_name)
    return any(t.get("status") == "pending" for t in tasks)


async def seed(state: AgentState, config) -> dict:
    tools = config["configurable"]["tools"]
    create = _tmap(tools).get("create_task")
    agent_name = state["agent_name"]

    src = src_label(agent_name)
    emit(src, "note", f"seed case={state['case_id']} run={state['run_id']}")

    if agent_name == "triage":
        if create:
            result = await _call(create, {
                "case_id": state["case_id"],
                "run_id": state["run_id"],
                "agent_name": "triage",
                "title": f"Triage case {state['case_id']}",
                "description": (
                    f"Analyst question: {state['question']}\n\n"
                    "Read the SOAR case and all linked alerts. "
                    "Diagnose the incident, identify distinct attack threads, "
                    "and return a triage report directly as your final task output. "
                    "Include a prioritized investigation plan in the report, but do "
                    "not write the triage report to AVFS and do not create "
                    "investigation queue tasks. The orchestrator will ask the analyst "
                    "before starting investigation."
                ),
                "priority": 100,
            })
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
            # Prefer a structured handoff (metadata); fall back to the legacy
            # string-embedded triage report for back-compat / direct calls.
            handoff = Handoff.from_dict(state.get("handoff"))
            has_triage = handoff is not None or "## Triage report" in state["question"]
            if has_triage:
                title = "Populate investigation queue from triage handoff"
                description = handoff.to_seed_text() if handoff else state["question"]
                seed_tag = "created triage handoff task"
                triage_text = handoff.triage_report if handoff else state["question"]
                _record_hypotheses_text(state, triage_text, source="triage handoff")
            else:
                title = f"Investigate case {state['case_id']}"
                description = (
                    f"{state['question']}\n\n"
                    "Use available SIEM and SOAR capabilities to investigate. "
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
            })
            if _is_error_tool_result(result):
                emit(src, "error", "seed: create_task FAILED", detail=str(result))
            else:
                emit(src, "note", seed_tag)
        elif already_seeded:
            emit(src, "note", "queue already populated, skipping seed")

    return {}


async def claim(state: AgentState, config) -> dict:
    if await _cancel_requested(state["run_id"]):
        emit(src_label(state["agent_name"]), "note", "cancel requested, stopping before next task claim")
        return {"status": "cancelled", "current_task": None}

    tools = config["configurable"]["tools"]
    claim_fn = _tmap(tools).get("claim_next")
    if claim_fn is None:
        return {"current_task": None}
    raw = await _call(claim_fn, {
        "case_id": state["case_id"],
        "run_id": state["run_id"],
        "agent_name": state["agent_name"],
    })
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        data = None
    # server returns {"task": <task_dict>} -- unwrap it
    if isinstance(data, dict) and "task" in data:
        data = data["task"]
    task = data if isinstance(data, dict) and "id" in data else None
    src = src_label(state["agent_name"])
    if task:
        emit(src, "task", f"[P{task.get('priority', '?')}] {task.get('title', '?')}",
             detail=json.dumps(task, indent=2, default=str))
    else:
        emit(src, "note", "queue empty, moving to finish")
    return {"current_task": task, "messages": []}


async def think(state: AgentState, config) -> dict:
    model = config["configurable"]["model"]
    tools = config["configurable"]["tools"]
    system_prompt = config["configurable"]["system_prompt"]
    src = src_label(state["agent_name"])

    messages = _sanitize_history(list(state["messages"]))
    if not messages:
        task = state["current_task"]
        task_text = f"**Task:** {task['title']}\n\n{task.get('description') or ''}".strip()

        # Inject cross-task board context for investigation tasks (not seed task)
        board_context = ""
        if (state["agent_name"] == "investigation"
                and "populate investigation queue" not in (task.get("title") or "").lower()):
            get_board_fn = _tmap(tools).get("get_board")
            if get_board_fn:
                raw = await _call(get_board_fn, {})
                board_context = _format_board_context(raw)

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=task_text + board_context),
        ]

    model_tools = _model_tools_for_agent(state["agent_name"], tools, state.get("current_task"))
    bound = model.bind_tools(model_tools)

    ctx_tokens = state.get("ctx_tokens", 0)
    if _should_compact(ctx_tokens):
        emit(src, "note", f"context compaction triggered ({ctx_tokens:,} tokens)")
        messages = await _compact_history(messages, bound, state["agent_name"])
        ctx_tokens = 0  # reset; will be updated from next response

    current_intent = (state.get("current_intent") or "").strip()
    if current_intent:
        messages.append(HumanMessage(content=(
            "[Public intent already shown to the analyst]\n"
            f"{current_intent}\n\n"
            "Perform that action now. Do not repeat the intent. Return tool calls when "
            "tools are needed, otherwise return the task result."
        )))

    response = await _invoke_bound_model(bound, messages, state["agent_name"])
    _sanitize_message(response)

    new_ctx = _extract_input_tokens(response) or ctx_tokens
    if new_ctx:
        update_context_usage(new_ctx, src)

    text = (response.content or "").strip()
    if text:
        emit(src, "think", summarize_think(text), detail=text)
    return {
        "messages": messages + [response],
        "steps": state["steps"] + 1,
        "ctx_tokens": new_ctx,
        "model_calls_made": state.get("model_calls_made", 0) + 1,
    }


async def intent(state: AgentState, config) -> dict:
    """Stream a public evidence/assessment/action summary before the next turn."""
    if await _cancel_requested(state["run_id"]):
        emit(src_label(state["agent_name"]), "note", "cancel requested before next action")
        return {"status": "cancelled", "current_intent": ""}

    sequence = state.get("intent_sequence", 0) + 1
    task = state.get("current_task") or {}
    tools = _model_tools_for_agent(
        state["agent_name"],
        config["configurable"]["tools"],
        state.get("current_task"),
    )
    result = await generate_public_intent(
        config["configurable"].get("intent_model") or config["configurable"]["model"],
        _sanitize_history(list(state.get("messages") or [])),
        source=src_label(state["agent_name"]),
        sequence=sequence,
        task_title=task.get("title", ""),
        available_tools=[getattr(tool, "name", "") for tool in tools],
    )
    return {
        "current_intent": result.text,
        "intent_sequence": sequence,
        "model_calls_made": state.get("model_calls_made", 0) + 1,
    }


# Hard cap on any single tool result fed back into the conversation. Prevents a
# pathological tool (e.g. a case linking thousands of alerts) from overflowing
# the model's context window. ~24k chars =~ 6k tokens.
_MAX_TOOL_RESULT_CHARS = 24000


def _cap_tool_result(content: str) -> str:
    if len(content) <= _MAX_TOOL_RESULT_CHARS:
        return content
    head = content[:_MAX_TOOL_RESULT_CHARS]
    return (
        f"{head}\n\n...[truncated {len(content) - _MAX_TOOL_RESULT_CHARS} chars -- "
        "result too large; narrow your query or request fewer items]"
    )


def _is_error_tool_result(content: str) -> bool:
    c = (content or "").strip()
    if c.startswith("Error:"):
        return True
    try:
        obj = json.loads(c)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    # AVFS-style envelope {"ok": bool, "data": ..., "error": null|msg}: a present
    # `error` key is NOT itself a failure — `error: null` with `ok: true` is success.
    # Only flag when the envelope says failure, or when a bare `error` is truthy.
    if "ok" in obj:
        return obj.get("ok") is False or bool(obj.get("error"))
    return bool(obj.get("error"))


def _expand_tilde_args(args: dict) -> dict:
    """Expand leading ~ in any string argument that looks like an AVFS path.

    The model is instructed to use ~/cases/... notation, but AVFS requires
    absolute paths. This runs before every tool call so the model's shorthand
    always resolves correctly regardless of which AVFS tool is invoked.
    """
    home = home_dir()
    expanded = {}
    for k, v in args.items():
        if isinstance(v, str) and (v == "~" or v.startswith("~/")):
            expanded[k] = home + v[1:]
        else:
            expanded[k] = v
    return expanded


async def _ensure_parent_dir(tmap: dict, path) -> None:
    """Create the parent directory of an AVFS path (mkdir -p). No-op if already present."""
    mkdir = tmap.get("mkdir")
    if not mkdir or not isinstance(path, str) or "/" not in path:
        return
    parent = path.rsplit("/", 1)[0]
    if parent:
        await _call(mkdir, {"path": parent, "parents": True})


async def use_tools(state: AgentState, config) -> dict:
    tools = config["configurable"]["tools"]
    tmap = _tmap(_model_tools_for_agent(state["agent_name"], tools))
    messages = list(state["messages"])
    last = messages[-1]
    new_calls = 0

    src = src_label(state["agent_name"])
    if await _cancel_requested(state["run_id"]):
        emit(src, "note", "cancel requested after intent; no tool was executed")
        return {"status": "cancelled", "current_intent": ""}

    intent_sequence = state.get("intent_sequence", 0)
    intent_metadata = (
        {"intent_sequence": intent_sequence}
        if (state.get("current_intent") or "").strip()
        else {}
    )

    for tc in last.tool_calls:
        args = tc.get("args", {})
        emit(
            src,
            "call",
            f"{tc['name']}({summarize_args(args)})",
            detail=json.dumps(args, indent=2, default=str),
            metadata=intent_metadata,
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
        "current_intent": "",
        "intent_sequence": intent_sequence,
    }


async def _finalize_triage_report(state: AgentState, config, messages: list) -> tuple[str, int]:
    """Recover the full triage report when the model stops without text."""
    model = config["configurable"]["model"]
    prompt = HumanMessage(
        content=(
            "Your last response was a brief observation — NOT a complete triage report. "
            "Write the full triage report now. Do NOT call any tools. "
            "The report must include ALL of the following sections:\n\n"
            "## Hypothesis\n"
            "<one-paragraph incident hypothesis>\n\n"
            "## Severity / Confidence\n"
            "<severity and confidence with evidence class for each major claim>\n\n"
            "## Key Pivots\n"
            "<users, hosts, IPs, rule IDs, timestamps>\n\n"
            "## Confirmed Facts\n"
            "<bullet list of facts backed by retrieved raw events, with event IDs>\n\n"
            "## SOAR-Only / Unverified\n"
            "<claims present in case/alert text but no raw event was retrieved>\n\n"
            "## Evidence Gaps\n"
            "<missing telemetry, unanswered questions>\n\n"
            "## Investigation Plan\n"
            "1. <specific question, pivots, time window, expected source>\n"
            "2. ...\n\n"
            "If you have zero work items, explain why this is a confirmed false positive "
            "with no follow-up needed. Otherwise include at least one numbered work item."
        )
    )
    response = await _invoke_bound_model(
        model,
        _sanitize_history(list(messages) + [prompt]),
        state["agent_name"],
    )
    _sanitize_message(response)

    new_ctx = _extract_input_tokens(response) or state.get("ctx_tokens", 0)
    if new_ctx:
        update_context_usage(new_ctx, src_label(state["agent_name"]))

    text = (response.content or "").strip()
    if text:
        emit(src_label(state["agent_name"]), "think", summarize_think(text), detail=text)
    return text, new_ctx


def _execution_record(messages: list) -> str:
    """Build a factual completion record from tool messages already in history."""
    entries: list[str] = []
    for message in messages:
        if not isinstance(message, ToolMessage):
            continue
        name = getattr(message, "name", "") or "tool"
        content = _normalize(getattr(message, "content", "") or "")
        entries.append(f"- `{name}`: {summarize_result(name, content)}")

    if entries:
        return (
            "The task reached completion without a final narrative from the agent.\n\n"
            "**Recorded tool activity:**\n" + "\n".join(entries) +
            "\n\nNo additional conclusion was supplied. Review the recorded tool "
            "results and linked artifacts before treating the task as a substantive finding."
        )
    return (
        "The task reached completion without a final narrative and without recorded "
        "tool activity. No findings or conclusion were supplied."
    )


async def _finalize_task_message(
    state: AgentState,
    config,
    messages: list,
) -> tuple[str, int]:
    """Recover a grounded completion message when a task ends with empty content."""
    task = state.get("current_task") or {}
    is_investigation_task = (
        state["agent_name"] == "investigation"
        and _SEED_TASK_TITLE not in (task.get("title") or "").lower()
    )
    if is_investigation_task:
        prompt_text = (
            "The current investigation task is ending, but your last response contained "
            "no completion message. Based only on the task conversation and tool results "
            "above, write the task result using EXACTLY this markdown template:\n\n"
            "## Confirmed Facts\n"
            "- <raw-evidence-backed fact with event ID or timestamp, or None confirmed.>\n\n"
            "## Findings\n\n"
            "<brief narrative of work performed, result, confidence, gaps, and relevant "
            "artifact paths or event IDs>\n\n"
            "## Hypotheses\n"
            "- <open/refined/refuted/confirmed claim, or No open hypotheses.>\n\n"
            "Do not call tools. Do not invent results. If the available history does not "
            "support a conclusion, say that in Findings and use '- None confirmed.'"
        )
    else:
        prompt_text = (
            "The current task is ending, but your last response contained no completion "
            "message. Based only on the task conversation and tool results above, write a "
            "concise task completion update. State what work was performed, the key result "
            "or outcome, any remaining uncertainty or blocker, and relevant artifact paths "
            "or event IDs. Do not call tools. Do not invent results. If the available history "
            "does not support a conclusion, explicitly say that the outcome is inconclusive."
        )
    prompt = HumanMessage(content=prompt_text)
    try:
        response = await _invoke_bound_model(
            config["configurable"]["model"],
            _sanitize_history(list(messages) + [prompt]),
            state["agent_name"],
        )
        _sanitize_message(response)
        text = (response.content or "").strip()
        new_ctx = _extract_input_tokens(response) or state.get("ctx_tokens", 0)
        if new_ctx:
            update_context_usage(new_ctx, src_label(state["agent_name"]))
        if text:
            emit(
                src_label(state["agent_name"]),
                "think",
                summarize_think(text),
                detail=text,
            )
            return text, new_ctx
    except Exception as exc:
        emit(
            src_label(state["agent_name"]),
            "warning",
            "task completion message recovery failed",
            detail=str(exc),
        )

    return _execution_record(messages), state.get("ctx_tokens", 0)


def _has_required_task_sections(text: str) -> bool:
    return bool(_CONFIRMED_FACTS_RE.search(text or "") and _HYPOTHESES_RE.search(text or ""))


def _wrap_investigation_template(text: str) -> str:
    body = (text or "").strip() or "No task narrative was supplied."
    return (
        "## Confirmed Facts\n"
        "- None confirmed.\n\n"
        "## Findings\n\n"
        f"{body}\n\n"
        "## Hypotheses\n"
        "- No open hypotheses."
    )


async def _ensure_investigation_task_template(
    state: AgentState,
    config,
    messages: list,
    final_answer: str,
) -> tuple[str, int]:
    """Force non-seed investigation task output into the board-parsable template."""
    task = state.get("current_task") or {}
    if (
        state["agent_name"] != "investigation"
        or _SEED_TASK_TITLE in (task.get("title") or "").lower()
        or _has_required_task_sections(final_answer)
    ):
        return final_answer, 0

    prompt = HumanMessage(content=(
        "Rewrite the current task result into the REQUIRED investigation template. "
        "Use only the task conversation, tool results, and the draft answer below. "
        "Preserve raw-event-backed facts with event IDs/timestamps under "
        "`## Confirmed Facts`; put unsupported observations in `## Findings`; put "
        "unresolved causal claims in `## Hypotheses`. Do not invent evidence. Return "
        "only markdown with these exact headers, in this order:\n\n"
        "## Confirmed Facts\n"
        "- <fact or None confirmed.>\n\n"
        "## Findings\n\n"
        "<analysis>\n\n"
        "## Hypotheses\n"
        "- <claim or No open hypotheses.>\n\n"
        "Draft answer to rewrite:\n\n"
        f"{(final_answer or '').strip() or '(empty)'}"
    ))
    try:
        response = await _invoke_bound_model(
            config["configurable"]["model"],
            _sanitize_history(list(messages) + [prompt]),
            state["agent_name"],
        )
        _sanitize_message(response)
        rewritten = (response.content or "").strip()
        new_ctx = _extract_input_tokens(response) or state.get("ctx_tokens", 0)
        if new_ctx:
            update_context_usage(new_ctx, src_label(state["agent_name"]))
        if _has_required_task_sections(rewritten):
            emit(
                src_label(state["agent_name"]),
                "note",
                "task output normalized to required findings template",
            )
            return rewritten, new_ctx
    except Exception as exc:
        emit(
            src_label(state["agent_name"]),
            "warning",
            "task template normalization failed",
            detail=str(exc),
        )

    emit(
        src_label(state["agent_name"]),
        "warning",
        "task output missing required findings template; wrapping as unconfirmed findings",
    )
    return _wrap_investigation_template(final_answer), state.get("ctx_tokens", 0)


# How many think cycles to allow before giving up on the model and creating tasks
# programmatically from the handoff.
_SEED_MAX_RETRIES = 2


def _extract_plan_items(triage_report: str) -> list[str]:
    """Pull numbered items from the investigation-plan section of a triage report."""
    lower = triage_report.lower()
    # Find the first recognisable plan header and start from there.
    plan_start = -1
    for header in ("investigation plan", "proposed investigation", "next steps",
                   "recommended actions", "work items"):
        idx = lower.find(header)
        if idx >= 0 and (plan_start < 0 or idx < plan_start):
            plan_start = idx
    text = triage_report[plan_start:] if plan_start >= 0 else triage_report
    items: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+[.)]\s+(.+)", line)
        if m:
            title = m.group(1).strip()
            if len(title) > 8:
                items.append(title)
    return items[:8]  # respect the triage hard-limit of 8 items


async def _create_tasks_from_handoff(
    state: AgentState, tools: list, existing_titles: set[str] | None = None
) -> int:
    """Programmatic fallback: parse the triage plan and call create_task for each item.

    Skips items whose lowercase title is already in existing_titles (e.g. tasks the
    model already created so we do not produce duplicates on a partial seed).
    """
    from ..agents.base import Handoff as _Handoff

    handoff = _Handoff.from_dict(state.get("handoff"))
    if not handoff:
        return 0
    items = _extract_plan_items(handoff.triage_report or "")
    if not items:
        return 0

    create_fn = _tmap(tools).get("create_task")
    if not create_fn:
        return 0

    skip = {t.lower() for t in (existing_titles or ())}
    src = src_label(state["agent_name"])
    created = 0
    for i, title in enumerate(items):
        if title.lower() in skip:
            emit(src, "note", f"seed fallback: skipping already-queued '{title[:60]}'")
            continue
        result = await _call(create_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
            "title": title[:200],
            "description": f"Triage investigation plan item {i + 1}.",
            "priority": max(30, 90 - i * 8),
        })
        if not _is_error_tool_result(result):
            created += 1
            emit(src, "note", f"seed fallback: queued '{title[:60]}'")
    emit(src, "note", f"seed fallback: {created}/{len(items)} tasks created from triage plan")
    return created


async def assess(state: AgentState, config) -> dict:
    tools = config["configurable"]["tools"]
    complete_fn = _tmap(tools).get("complete_task")
    last = state["messages"][-1]
    task = state.get("current_task")
    final_answer = (last.content or "").strip()
    new_ctx = state.get("ctx_tokens", 0)
    if state["agent_name"] == "triage" and (
        not final_answer or not _extract_plan_items(final_answer)
    ):
        final_answer, new_ctx = await _finalize_triage_report(state, config, state["messages"])
    if not final_answer:
        final_answer, new_ctx = await _finalize_task_message(
            state,
            config,
            state["messages"],
        )
    final_answer, normalized_ctx = await _ensure_investigation_task_template(
        state,
        config,
        state["messages"],
        final_answer,
    )
    new_ctx = normalized_ctx or new_ctx

    # Seed guard: if the model completed the queue-population task without creating
    # all triage plan items, either re-inject the instruction (up to _SEED_MAX_RETRIES)
    # or create the missing tasks programmatically from the handoff.
    if (task and state["agent_name"] == "investigation"
            and _SEED_TASK_TITLE in (task.get("title") or "").lower()):
        from ..agents.base import Handoff as _Handoff
        all_tasks = await _list_tasks(
            tools, state["case_id"], state["run_id"], state["agent_name"]
        )
        # Exclude the seed task itself; count only investigation sub-tasks.
        sub_tasks = [t for t in all_tasks
                     if _SEED_TASK_TITLE not in (t.get("title") or "").lower()]
        pending_count = sum(1 for t in sub_tasks if t.get("status") == "pending")
        handoff = _Handoff.from_dict(state.get("handoff"))
        expected = len(_extract_plan_items((handoff.triage_report or "") if handoff else ""))
        under_populated = pending_count < max(1, expected)
        src = src_label(state["agent_name"])
        if under_populated:
            emit(src, "note",
                 f"seed guard: {pending_count} task(s) found, expected ~{expected} "
                 "from triage plan")
            if pending_count == 0 and state["steps"] <= _SEED_MAX_RETRIES:
                emit(src, "note",
                     f"seed guard (attempt {state['steps']}/{_SEED_MAX_RETRIES}): "
                     "no tasks created — re-injecting create_task instruction")
                correction = HumanMessage(content=(
                    "You have not called `create_task` yet. Your ONLY job right now is to "
                    "call `create_task` once for every numbered item in the triage "
                    "investigation plan above. Do not call `complete_task`, write files, or "
                    "run any SIEM queries until all tasks are created. Call `create_task` now."
                ))
                return {
                    "current_task": task,
                    "messages": list(state["messages"]) + [correction],
                    "final_answer": "",
                    "ctx_tokens": new_ctx,
                    "status": "_seed_retry",
                }
            # Partial seed or retry limit reached — fill in the missing tasks.
            emit(src, "warning",
                 f"seed guard: only {pending_count}/{expected} task(s) created — "
                 "filling in missing items from triage handoff")
            existing_titles = {(t.get("title") or "").lower() for t in sub_tasks}
            await _create_tasks_from_handoff(state, tools, existing_titles)

    summary = final_answer if state["agent_name"] == "triage" else final_answer[:1200]
    if complete_fn and task:
        await _call(complete_fn, {"task_id": task["id"], "summary": summary})
        emit(src_label(state["agent_name"]), "note",
             f"completed '{task.get('title', task['id'])}' "
             f"(steps={state['steps']}, calls={state['tool_calls_made']})",
             detail=summary)
    return {
        "current_task": None,
        "messages": [],
        "final_answer": final_answer,
        "ctx_tokens": new_ctx,
        "current_intent": "",
        "status": "",
    }


def _format_board_context(raw: str) -> str:
    """Format a get_board JSON response as a compact board context string."""
    if not raw or _is_error_tool_result(raw):
        return ""
    try:
        data = json.loads(raw)
        entries = data.get("entries", []) if isinstance(data, dict) else []
    except Exception:
        return ""
    if not entries:
        return ""

    artifacts = [e for e in entries if e.get("kind") == "artifact"]
    facts = [e for e in entries if e.get("kind") == "fact"]
    hyps = [e for e in entries if e.get("kind") == "hypothesis"]
    lines = [
        "\n\n---",
        "**Findings Board (use this state in the current task):**",
    ]
    if artifacts:
        lines.append("*Found artifacts — use these as pivots where relevant:*")
        for e in artifacts:
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- {e['content']}{src}")
    if facts:
        lines.append("*Confirmed facts — treat as established unless contradicted by newer evidence:*")
        for e in facts:
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- {e['content']}{src}")
    if hyps:
        lines.append(
            "*Hypotheses — when one becomes confirmed or refuted, restate it in your "
            "`## Hypotheses` section prefixed with `[Confirmed]` or `[Refuted]` (same "
            "wording); the board reconciles its status automatically:*"
        )
        for e in hyps:
            status = e.get("status", "open")
            conf = e.get("confidence", "")
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- [{status}/{conf}] {e['content']}{src}")
    lines.append(
        "Use the Findings Board actively: pivot on relevant artifacts, build on confirmed "
        "facts, and report how the current work changes each applicable hypothesis."
    )
    lines.append("---")
    return "\n".join(lines)


# Match the ## New Leads section header (h2, h3, or bold variant).
_NEW_LEADS_HEADER_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))New Leads(?:\*\*)?\s*\n",
    re.IGNORECASE,
)

# Match individual lead entries. Allow optional blank lines between fields and
# tolerate indentation variance. `pivots:` is optional so a title-only lead still
# registers (priority defaults to 50 when absent).
_NEW_LEADS_RE = re.compile(
    r"-\s+title:\s*[\"']?(.+?)[\"']?\s*\n"
    r"(?:[ \t]*\n)*"                         # optional blank lines
    r"\s+pivots:\s*(.+?)\s*\n"
    r"(?:[ \t]*\n)*"
    r"\s+priority:\s*(\d+)",
    re.MULTILINE,
)

# Accept h2, h3, or bold variants — small models sometimes use ### or **...**
_CONFIRMED_FACTS_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Confirmed Facts(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_HYPOTHESES_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Hypotheses(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_SECTION_HEADER_RE = re.compile(
    r"\n(?:#{2,6}\s+[^\n]+|\*\*[^\n*]+\*\*\s*)\n",
    re.IGNORECASE,
)


def _section_body(text: str, match: re.Match) -> str:
    """Return the body after a markdown section header until the next section."""
    rest = (text or "")[match.end():]
    next_header = _SECTION_HEADER_RE.search(rest)
    return rest[:next_header.start()] if next_header else rest

# Regex to parse a bullet like "- Crontab modified at ... (event ...)."
# Grabs everything after the leading "- ".
_FACT_BULLET_RE = re.compile(r"^\s*-\s+(.+)$", re.MULTILINE)

# Placeholder bullets the model emits when a section has no content. Recording
# these as facts/hypotheses is noise, so both paths skip them.
_NONE_BULLETS = frozenset({
    "none", "none.", "none confirmed", "none confirmed.",
    "no facts confirmed", "no facts confirmed.",
    "no open hypotheses", "no open hypotheses.",
    "no new leads", "no new leads.",
})

# Placeholder "nothing found" bullets the model emits in many phrasings
# ("None confirmed in this task.", "No confirmed findings", "N/A", ...). These
# are honest per-task negatives but are pure noise once aggregated into the
# report's Key Findings / Confirmed Facts / Hypotheses lists, so they must be
# dropped there. Match on a normalized prefix so variants are all caught.
_NONE_PREFIXES = (
    "none confirmed", "no facts confirmed", "no confirmed", "no open hypotheses",
    "no new leads", "no open leads", "no hypotheses", "no findings",
)


def _is_none_bullet(text: str) -> bool:
    """True for placeholder 'nothing found' bullets in any common phrasing."""
    t = (text or "").strip().strip("-*• ").lower()
    if not t or t in _NONE_BULLETS or t in {"none", "none.", "n/a", "n/a."}:
        return True
    return any(t.startswith(p) for p in _NONE_PREFIXES)


def _is_provenance_only(content: str) -> bool:
    r"""True for facts that are just an event-id/timestamp with no actual claim.

    The model sometimes dumps `Event \`abc123\` - 2025-04-20T03:41:00Z` as a fact.
    After stripping event-id tokens and timestamps, nothing of substance remains,
    so it is provenance, not a finding. Keep the threshold low (<=1 content word)
    so real but terse facts are never dropped.
    """
    key = _normalize_fact_key(content)
    words = [w for w in re.findall(r"[a-z0-9]+", key) if w not in {"event", "id", "ids", "alert", "at"}]
    return len(words) <= 1


# A Wazuh-style event id: digits-bearing token (optionally `~`-prefixed or
# dotted), length >= 6, no path/space chars. Used to merge facts that are just
# rewordings of the SAME event while keeping facts about DIFFERENT events.
_EVENT_ID_TOKEN_RE = re.compile(r"^~?[A-Za-z0-9][A-Za-z0-9._-]{5,}$")


def _event_ids_in(content: str) -> frozenset[str]:
    ids: set[str] = set()
    for backtick, evid in _SOURCE_REF_RE.findall(_ascii_dashes(content)):
        ref = (backtick or evid).strip()
        if not ref or "/" in ref or " " in ref:
            continue  # paths, commands, cron lines are content, not event ids
        if any(ch.isdigit() for ch in ref) and _EVENT_ID_TOKEN_RE.match(ref):
            ids.add(ref.lower())
    return frozenset(ids)


def _fact_dedup_key(content: str) -> str:
    """Dedup key that merges rewordings of one event but keeps distinct events.

    Two facts collapse only when they cite the same event id(s); facts citing
    different ids (e.g. five PAM logins at five timestamps) stay separate. Facts
    with no event id fall back to volatility-stripped text.
    """
    ids = _event_ids_in(content)
    if ids:
        return "ids:" + ",".join(sorted(ids))
    return _normalize_fact_key(content)

# Markers the model prepends to a restated hypothesis, in any combination/order:
#   bold/emphasis (`**`/`__`), an entry id the board context showed it
#   (`[id=entry_..]`), and/or a status (`[Open]`/`[Confirmed]`/`[Refuted]`).
_STATUS_TOKEN_RE = re.compile(
    r"\[\s*(open|confirmed|refuted)\s*(?:/\s*[a-z]+\s*)?\]", re.IGNORECASE
)
_ID_MARKER_RE = re.compile(r"\[\s*id\s*=\s*[A-Za-z0-9_]+\s*\]", re.IGNORECASE)
_EMPH_RE = re.compile(r"\*\*|__")
# Bullets that are leads/questions, not hypotheses (claims). Skip these.
_NON_HYPOTHESIS_RE = re.compile(
    r"^(investigate|determine|check|retrieve|identify|examine|review|find out|"
    r"what|which|who|where|when|how|did|does|do|is|are|was|were)\b",
    re.IGNORECASE,
)
# Event-id tokens (backtick-wrapped or after "event"/"id") and ISO timestamps —
# volatile provenance that should not defeat fact/hypothesis dedup, and that we
# can harvest as a fact's `source`.
_SOURCE_REF_RE = re.compile(
    r"`([^`]+)`|\bevent[ _]?(?:id)?[:\s]+([A-Za-z0-9_\-]{6,})",
    re.IGNORECASE,
)
# Match an ISO datetime, optionally with fractional seconds and a (possibly
# space-separated) zone — model output writes "2025-04-20 03:41:00.570 Z".
_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?\s*(?:Z|UTC|[+-]\d{2}:?\d{2})?"
)
# Unicode dashes (non-breaking hyphen, en/em dash, minus) and exotic spaces
# (nbsp, narrow/thin nbsp, word joiner) that the model emits in dates and
# timestamps and which otherwise defeat the ISO/dedup regexes above — e.g.
# "2025‑04‑20 03:41:00" has a narrow no-break space the `[T ]` class misses.
_CHAR_TRANSLATION = {ord(c): "-" for c in "‐‑‒–—―−"}
_CHAR_TRANSLATION.update(
    {cp: " " for cp in (
        0x00A0, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
        0x2009, 0x200A, 0x202F, 0x205F, 0x2060, 0xFEFF,
    )}
)


def _ascii_dashes(text: str) -> str:
    """Fold Unicode dashes/exotic spaces to ASCII so date/id regexes match."""
    return (text or "").translate(_CHAR_TRANSLATION)
# A "fact" that is just a list of event ids is provenance, not a finding.
_EVENT_ID_DUMP_RE = re.compile(r"^\s*event\s+ids?\s*[:\-]", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
_BRUTE_FORCE_RE = re.compile(
    r"\b(brute[ -]?force|failed ssh|failed password|authentication failure|auth(?:entication)? failed)\b",
    re.IGNORECASE,
)
_REVERSE_SHELL_RE = re.compile(
    r"(reverse shell|/dev/tcp/|sh\s+-i|bash\s+-i|nc\s+-e|netcat)",
    re.IGNORECASE,
)
_PERSISTENCE_RE = re.compile(r"\b(crontab|cron|persistence|scheduled task)\b", re.IGNORECASE)
_TROJAN_RE = re.compile(r"\b(trojaned|rootkit|known bad|malicious binary)\b", re.IGNORECASE)
_ANTI_FORENSIC_RE = re.compile(
    r"\b(wazuh-agent|agent restart|agent stopped|anti-forensic|tamper|impair defenses)\b",
    re.IGNORECASE,
)
_NEGATED_EVIDENCE_RE = re.compile(
    r"\b(no evidence of|no\s+.+\s+found|not observed|without|refuted)\b",
    re.IGNORECASE,
)


def _strip_markers(text: str) -> tuple[str, str | None]:
    """Peel leading bold / [id=..] / [status] markers; return (clean, status).

    The small model mixes these in any order (e.g. `**[id=x]** [Refuted] ...`),
    so peel iteratively until none remain.
    """
    s = (text or "").strip()
    status: str | None = None
    changed = True
    while changed and s:
        changed = False
        s2 = s.lstrip("* _")
        if s2 != s:
            s, changed = s2, True
        m = _STATUS_TOKEN_RE.match(s)
        if m:
            status = m.group(1).lower()
            s, changed = s[m.end():].strip(), True
        m = _ID_MARKER_RE.match(s)
        if m:
            s, changed = s[m.end():].strip(), True
    return s.strip(), status


def _looks_like_lead(text: str) -> bool:
    """True when a bullet is a question/imperative (a lead), not a hypothesis."""
    t = (text or "").strip()
    return t.endswith("?") or bool(_NON_HYPOTHESIS_RE.match(t))


def _extract_source_refs(text: str) -> str:
    """Collect event-id tokens / ISO timestamps cited in a bullet, for `source`."""
    refs: list[str] = []
    for backtick, evid in _SOURCE_REF_RE.findall(text or ""):
        ref = (backtick or evid).strip()
        if ref and ref not in refs:
            refs.append(ref)
    for ts in _ISO_TS_RE.findall(text or ""):
        if ts not in refs:
            refs.append(ts)
    return ", ".join(refs)


def _lines_with_ips(text: str, pattern: re.Pattern) -> set[str]:
    ips: set[str] = set()
    for line in (text or "").splitlines():
        if pattern.search(line) and not _NEGATED_EVIDENCE_RE.search(line):
            ips.update(_IP_LITERAL_RE.findall(line))
    return ips


def _has_positive_pattern(text: str, pattern: re.Pattern) -> bool:
    return any(
        pattern.search(line) and not _NEGATED_EVIDENCE_RE.search(line)
        for line in (text or "").splitlines()
    )


def _derive_report_guardrails(
    artifacts: list[dict],
    facts: list[dict],
    hypotheses: list[dict],
    completed: list[dict],
) -> tuple[list[str], str]:
    """Deterministic SOC-quality hints for the final report synthesis.

    These are derived from already-recorded board/task text. They do not introduce
    new evidence; they prevent the narrative model from under-calling obvious
    correlations or severity floors.
    """
    evidence_hypotheses = [
        entry for entry in hypotheses if entry.get("status") == "confirmed"
    ]
    corpus_parts: list[str] = []
    for entry in [*artifacts, *facts, *evidence_hypotheses]:
        corpus_parts.append((entry.get("content") or "").strip())
        if entry.get("source"):
            corpus_parts.append(str(entry["source"]))
    for task in completed:
        corpus_parts.append((task.get("title") or "").strip())
        corpus_parts.append((task.get("summary") or "").strip())
    corpus = "\n".join(part for part in corpus_parts if part)

    attacker_ips = _lines_with_ips(corpus, _BRUTE_FORCE_RE)
    c2_ips = _lines_with_ips(corpus, _REVERSE_SHELL_RE)
    linked_ips = sorted(attacker_ips & c2_ips)

    has_reverse_shell = _has_positive_pattern(corpus, _REVERSE_SHELL_RE)
    has_persistence = _has_positive_pattern(corpus, _PERSISTENCE_RE)
    has_trojaned = _has_positive_pattern(corpus, _TROJAN_RE)
    has_anti_forensic = _has_positive_pattern(corpus, _ANTI_FORENSIC_RE)

    derived_findings: list[str] = []
    guidance: list[str] = []
    if linked_ips:
        ip_list = ", ".join(linked_ips)
        derived_findings.append(
            f"- Correlation: reverse-shell/C2 destination {ip_list} matches the "
            f"brute-force source {ip_list}; treat those threads as linked."
        )
        guidance.append(
            "A discovered reverse-shell/C2 destination matches the original brute-force "
            "source IP. State this as the decisive linkage when writing the verdict."
        )
    if has_reverse_shell:
        guidance.append(
            "Confirmed reverse-shell/C2 evidence is a confirmed compromise indicator, "
            "not merely suspicious local administration."
        )
    if has_reverse_shell and (has_persistence or has_trojaned or has_anti_forensic):
        guidance.append(
            "Severity floor: critical. Reverse shell plus persistence, trojaned binaries, "
            "or agent tampering requires immediate containment."
        )
    elif has_reverse_shell or has_trojaned:
        guidance.append(
            "Severity floor: high. Reverse shell or trojaned-binary evidence requires "
            "containment unless the facts explicitly refute compromise."
        )
    if has_anti_forensic:
        guidance.append("Call out security-agent tampering as anti-forensic activity.")

    return derived_findings, "\n".join(f"- {item}" for item in guidance)


def _normalize_fact_key(text: str) -> str:
    """Dedup key for a fact/hypothesis: drop markers and volatile provenance.

    Strips id/status markers and emphasis so a restated entry (with or without a
    `[id=..]`/`[Refuted]`/`**bold**` prefix) collapses onto the original.
    """
    cleaned = _ascii_dashes(text or "")
    cleaned = _ID_MARKER_RE.sub(" ", cleaned)
    cleaned = _STATUS_TOKEN_RE.sub(" ", cleaned)
    cleaned = _EMPH_RE.sub(" ", cleaned)
    cleaned = _SOURCE_REF_RE.sub(" ", cleaned)
    cleaned = _ISO_TS_RE.sub(" ", cleaned)
    # collapse leftover punctuation/whitespace and parenthetical provenance husks
    cleaned = re.sub(r"\(\s*(?:event|id|@?timestamp)?[ ,;:]*\)", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s`(),]+", " ", cleaned)
    return cleaned.strip().lower()


def _record_board_entry(
    state: AgentState,
    *,
    kind: str,
    content: str,
    source: str = "",
    confidence: str = "medium",
    status: str = "open",
    dedup_key: str | None = None,
) -> None:
    from aci_board import store

    store.init_db()
    store.add_entry(
        case_id=state["case_id"],
        run_id=state["run_id"],
        agent_name=state["agent_name"],
        kind=kind,
        content=content,
        source=source,
        confidence=confidence,
        status=status,
        dedup_key=dedup_key,
    )


def _record_hypotheses_text(
    state: AgentState,
    text: str,
    *,
    source: str = "",
) -> int:
    """Persist `## Hypotheses` bullets as upserts.

    A bullet may carry leading markers (`**bold**`, `[id=..]`, `[Refuted]`,
    `[Confirmed]`, `[Open]`). When the cleaned content matches an existing
    hypothesis (ignoring those markers and volatile event ids/timestamps), update
    that entry's status instead of adding a duplicate row. Questions/imperatives
    (leads) are skipped.
    """
    match = _HYPOTHESES_RE.search(text or "")
    if not match:
        return 0
    block = _section_body(text, match)

    from aci_board import store
    store.init_db()
    existing = [
        e for e in store.list_entries(
            state["case_id"], state["run_id"], state["agent_name"]
        ) if e.get("kind") == "hypothesis"
    ]
    by_key = {(e.get("dedup_key") or "").strip().lower(): e for e in existing}

    created = 0
    for bullet in _FACT_BULLET_RE.finditer(block):
        raw = bullet.group(1).strip()
        content, status = _strip_markers(raw)
        if not content or _is_none_bullet(content):
            continue
        if _looks_like_lead(content):
            # A question/imperative is a lead, not a hypothesis.
            continue
        key = _normalize_fact_key(content)
        match_entry = by_key.get(key)
        if match_entry:
            # Only transition status when the bullet declares one.
            if status and match_entry.get("status") != status:
                store.update_entry(match_entry["id"], status=status, content=content)
            continue
        new_entry = store.add_entry(
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
            kind="hypothesis",
            content=content,
            source=source,
            confidence="medium",
            status=status or "open",
            dedup_key=key,
        )
        by_key[key] = new_entry
        created += 1
    return created


async def pivot(state: AgentState, config) -> dict:
    """After each task: update the Findings Board, parse new leads,
    and create follow-up tasks. No model call — purely structural.
    """
    if state["agent_name"] != "investigation":
        return {}

    tools = config["configurable"]["tools"]
    tmap = _tmap(tools)
    final_answer = state.get("final_answer", "")
    src = src_label(state["agent_name"])

    # Push confirmed facts from "## Confirmed Facts" section to the board.
    # Accept ## / ### / **Confirmed Facts** variants (small models vary in heading level).
    # Recorded via the store path (not the add_fact MCP tool) so we can attach the
    # cited event ids/timestamps as `source` and dedup on a volatility-stripped key.
    _cf_match = _CONFIRMED_FACTS_RE.search(final_answer) if final_answer else None
    if _cf_match:
        facts_block = _section_body(final_answer, _cf_match)
        for m in _FACT_BULLET_RE.finditer(facts_block):
            content, _ = _strip_markers(m.group(1).strip())
            if not content or _is_none_bullet(content):
                continue
            # Skip dangling lead-ins ("...appended:") and bare provenance dumps
            # ("Event IDs: a, b, c") — these are not findings.
            if content.rstrip().endswith(":") or _EVENT_ID_DUMP_RE.match(content):
                continue
            _record_board_entry(
                state,
                kind="fact",
                content=content,
                source=_extract_source_refs(content),
                confidence="high",
                status="confirmed",
                dedup_key=_normalize_fact_key(content),
            )
            emit(src, "note", "findings board: fact added")

    # Hypotheses are structural output, so persist them deterministically even if
    # the model does not choose the add_hypothesis tool.
    _hyp_match = _HYPOTHESES_RE.search(final_answer) if final_answer else None
    if _hyp_match:
        created_hypotheses = _record_hypotheses_text(state, final_answer)
        for _ in range(created_hypotheses):
            emit(src, "note", "findings board: hypothesis added")

    _nl_match = _NEW_LEADS_HEADER_RE.search(final_answer) if final_answer else None
    if not _nl_match:
        return {}

    leads_section = _section_body(final_answer, _nl_match)
    leads = _NEW_LEADS_RE.findall(leads_section)
    emit(src, "note", f"pivot: parsed {len(leads)} lead(s) from New Leads section")
    if not leads:
        return {}

    create_fn = tmap.get("create_task")
    list_fn = tmap.get("list_tasks")
    if not create_fn:
        return {}

    existing_titles: set[str] = set()
    if list_fn:
        raw = await _call(list_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
        })
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            tasks = data if isinstance(data, list) else data.get("tasks", [])
            existing_titles = {(t.get("title") or "").lower() for t in tasks}
        except Exception:
            pass

    src = src_label(state["agent_name"])
    created = 0
    for title, pivots, priority_str in leads:
        title = title.strip()
        if title.lower() in existing_titles:
            emit(src, "note", f"pivot: skipping duplicate '{title}'")
            continue
        result = await _call(create_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
            "title": title,
            "description": f"Pivots: {pivots.strip()}",
            "priority": int(priority_str),
        })
        if not _is_error_tool_result(result):
            existing_titles.add(title.lower())
            created += 1
            emit(src, "note", f"pivot: created '{title}' (P{priority_str})")
            _record_board_entry(
                state,
                kind="hypothesis",
                content=title,
                source=f"Pivots: {pivots.strip()}",
                confidence="low",
                status="open",
            )
        else:
            emit(src, "error", f"pivot: create_task failed for '{title}'", detail=result)

    if created:
        emit(src, "note", f"pivot: {created} follow-up task(s) queued")
    return {}


async def _build_investigation_summary(state: AgentState, tmap: dict, model=None) -> str:
    """Read the task queue and board, then compile the final investigation report.

    Produces a synthesized SOC analyst report (verdict, executive summary, timeline,
    scope/impact, recommendations, open gaps) via one model call over the COMPLETE
    board, followed by the deterministic structured findings as an appendix so the
    full grounded detail is always preserved. Runs at the end of every investigation
    so the orchestrator and analyst receive a complete, decision-useful picture.
    """
    # --- task queue ---
    list_fn = tmap.get("list_tasks")
    tasks: list[dict] = []
    if list_fn:
        raw = await _call(list_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
        })
        if not _is_error_tool_result(raw):
            try:
                data = json.loads(raw)
                tasks = data if isinstance(data, list) else data.get("tasks", [])
            except Exception:
                pass

    completed = [t for t in tasks if t.get("status") == "completed"
                 and _SEED_TASK_TITLE not in (t.get("title") or "").lower()]
    incomplete = [t for t in tasks if t.get("status") not in ("completed", "dismissed")
                  and _SEED_TASK_TITLE not in (t.get("title") or "").lower()]

    # --- board ---
    get_board_fn = tmap.get("get_board")
    artifacts: list[dict] = []
    facts: list[dict] = []
    hypotheses: list[dict] = []
    if get_board_fn:
        raw = await _call(get_board_fn, {})
        if not _is_error_tool_result(raw):
            try:
                data = json.loads(raw)
                entries = data.get("entries", []) if isinstance(data, dict) else []
                artifacts = [e for e in entries if e.get("kind") == "artifact"]
                facts = [e for e in entries if e.get("kind") == "fact"]
                hypotheses = [e for e in entries if e.get("kind") == "hypothesis"]
            except Exception:
                pass

    # --- compose deterministic structured findings (the grounded appendix) ---
    lines: list[str] = [
        f"# Structured Findings — Case {state['case_id']}",
        f"**Run:** {state['run_id']}  \n**Question:** {state['question']}",
        "",
    ]

    # Lead with the confirmed findings so the most important results (e.g. a
    # confirmed reverse shell) are at the top, not buried in a per-task appendix.
    # Built deterministically from the board: all facts + confirmed hypotheses.
    # Collapse near-duplicate facts: the model restates the same fact across
    # tasks with only the event-id / timestamp differing, so dedup on a
    # volatility-stripped key (not exact text) and drop placeholder negatives.
    key_findings: list[str] = []
    seen_findings: set[str] = set()
    for fact in facts:
        content = (fact.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _is_provenance_only(content):
            continue
        key = _fact_dedup_key(content) or content.lower()
        if key in seen_findings:
            continue
        seen_findings.add(key)
        src = f" [{fact['source']}]" if fact.get("source") else ""
        key_findings.append(f"- {content}{src}")
    for hyp in hypotheses:
        if hyp.get("status") != "confirmed":
            continue
        content = (hyp.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _looks_like_lead(content):
            continue
        key = _normalize_fact_key(content) or content.lower()
        if key in seen_findings:
            continue
        seen_findings.add(key)
        key_findings.append(f"- {content} (confirmed)")
    derived_findings, report_guardrails = _derive_report_guardrails(
        artifacts, facts, hypotheses, completed
    )
    for finding in derived_findings:
        key = finding.lower()
        if key not in seen_findings:
            seen_findings.add(key)
            key_findings.append(finding)

    lines.append("## Key Findings")
    if key_findings:
        lines.extend(key_findings)
    else:
        lines.append("- No confirmed findings; see Hypotheses and Completed Tasks below.")
    lines.append("")

    if artifacts:
        lines.append("## Found Artifacts")
        for artifact in artifacts:
            src = f" [{artifact['source']}]" if artifact.get("source") else ""
            lines.append(f"- {artifact['content']}{src}")
        lines.append("")

    # Dedup + drop placeholder negatives so the appendix mirrors Key Findings.
    fact_lines: list[str] = []
    seen_facts: set[str] = set()
    for fact in facts:
        content = (fact.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _is_provenance_only(content):
            continue
        key = _fact_dedup_key(content) or content.lower()
        if key in seen_facts:
            continue
        seen_facts.add(key)
        src = f" [{fact['source']}]" if fact.get("source") else ""
        fact_lines.append(f"- {content}{src}")
    if fact_lines:
        lines.append("## Confirmed Facts")
        lines.extend(fact_lines)
        lines.append("")

    # Collapse duplicate hypotheses onto one entry, preferring a resolved
    # status (confirmed/refuted) over open so the same claim never appears as
    # both [open] and [refuted]. Drop placeholder negatives and stray leads.
    _STATUS_RANK = {"confirmed": 3, "refuted": 2, "open": 1}
    hyp_by_key: dict[str, dict] = {}
    for hyp in hypotheses:
        raw = (hyp.get("content") or "").strip()
        # The model often embeds the status (and confidence) as a literal prefix
        # inside the content (`[confirmed/medium] ...`). Peel it for clean display
        # and trust it over a stale DB status when present.
        content, embedded_status = _strip_markers(raw)
        if not content or _is_none_bullet(content) or _looks_like_lead(content):
            continue
        status = embedded_status or hyp.get("status", "open")
        key = _normalize_fact_key(content) or content.lower()
        prev = hyp_by_key.get(key)
        if prev is None or _STATUS_RANK.get(status, 0) > _STATUS_RANK.get(prev["status"], 0):
            hyp_by_key[key] = {
                "content": content,
                "status": status,
                "confidence": hyp.get("confidence", "medium"),
            }
    if hyp_by_key:
        lines.append("## Hypotheses")
        for h in hyp_by_key.values():
            lines.append(f"- [{h['status']}/{h['confidence']}] {h['content']}")
        lines.append("")

    if completed:
        lines.append("## Completed Tasks")
        for t in completed:
            lines.append(f"### {t.get('title', '(untitled)')}")
            summary = (t.get("summary") or "").strip()
            if summary:
                lines.append(summary)
            lines.append("")

    if incomplete:
        lines.append("## Incomplete / Pending Tasks")
        for t in incomplete:
            status = t.get("status", "unknown")
            lines.append(f"- [{status}] {t.get('title', '(untitled)')}")
        lines.append("")

    if not completed and not artifacts and not facts and not hypotheses:
        lines.append("No tasks completed and no Findings Board entries were recorded.")

    structured = "\n".join(lines)

    # Synthesize a SOC analyst report on top of the grounded data. The model sees
    # the COMPLETE board + task summaries (never truncated); the structured findings
    # are kept as an appendix so nothing is lost if the synthesis is terse.
    narrative = await _synthesize_analyst_report(
        model, state, key_findings, facts, hypotheses, completed, report_guardrails
    )
    if narrative:
        return f"{narrative}\n\n---\n\n# Appendix — Structured Findings\n\n{structured}"
    return structured


_ANALYST_REPORT_SYSTEM = (
    "You are a senior SOC analyst writing the final incident report from an "
    "investigation's confirmed findings. Use ONLY the evidence provided — never "
    "invent event IDs, IPs, hosts, users, timestamps, or facts. Correlate "
    "indicators: if a discovered destination/C2 address matches the original "
    "attacker source, or local privileged activity aligns in time with the alert, "
    "state the linkage explicitly. Be decisive and calibrated."
)


def _entry_line(e: dict) -> str:
    content = (e.get("content") or "").strip()
    src = f" [{e['source']}]" if e.get("source") else ""
    status = e.get("status")
    tag = f"[{status}] " if status and status not in ("observed",) else ""
    return f"- {tag}{content}{src}"


async def _synthesize_analyst_report(
    model, state: AgentState, key_findings: list[str],
    facts: list[dict], hypotheses: list[dict], completed: list[dict],
    report_guardrails: str = "",
) -> str:
    """One grounded model call → an analyst-grade narrative. '' on any failure."""
    if model is None:
        return ""
    # Cap lists so the synthesis prompt stays within small-model context limits.
    facts_txt = "\n".join(_entry_line(f) for f in facts[:60]) or "- (none)"
    hyps_txt = "\n".join(_entry_line(h) for h in hypotheses[:30]) or "- (none)"
    tasks_txt = "\n\n".join(
        f"### {t.get('title', '(untitled)')}\n{(t.get('summary') or '').strip()[:600] or '(no summary)'}"
        for t in completed
    ) or "- (none)"
    findings_txt = "\n".join(key_findings) or "- (none)"
    guardrails_txt = report_guardrails or "- No deterministic severity/correlation guardrails derived."
    prompt = (
        f"Case: {state['case_id']}\nAnalyst question: {state['question']}\n\n"
        f"## Key findings already derived\n{findings_txt}\n\n"
        f"## Deterministic analysis guardrails\n{guardrails_txt}\n\n"
        f"## Confirmed facts (raw-evidence backed)\n{facts_txt}\n\n"
        f"## Hypotheses (with status)\n{hyps_txt}\n\n"
        f"## Completed investigation tasks\n{tasks_txt}\n\n"
        "Write the final report in markdown with EXACTLY these sections:\n"
        "## Verdict — one line: compromise confirmed / suspected / false positive; "
        "severity (low/medium/high/critical); active or contained.\n"
        "## Executive Summary — 2-4 sentences a manager can act on.\n"
        "## Timeline — chronological bullets with timestamps and event IDs.\n"
        "## Scope & Impact — affected hosts/users/accounts; what the attacker achieved.\n"
        "## Recommended Actions — prioritized, concrete containment/remediation.\n"
        "## Open Gaps — what could not be confirmed and why.\n"
        "Ground every claim in the facts above. Follow the deterministic guardrails "
        "unless the facts explicitly contradict them. If facts are thin, say so in the verdict."
    )
    try:
        resp = await model.ainvoke([
            SystemMessage(content=_ANALYST_REPORT_SYSTEM),
            HumanMessage(content=prompt),
        ])
        _sanitize_message(resp)
        return (getattr(resp, "content", "") or "").strip()
    except Exception as exc:
        emit(src_label(state["agent_name"]), "warning",
             "final report synthesis failed; using structured findings only",
             detail=str(exc))
        return ""


async def finish(state: AgentState, config) -> dict:
    if state.get("status") == "cancelled":
        emit(src_label(state["agent_name"]), "done", "cancelled")
        return {
            "status": "cancelled",
            "final_answer": state.get("final_answer") or f"{state['agent_name']} cancelled.",
        }

    tools = config["configurable"]["tools"]
    tmap = _tmap(tools)
    src = src_label(state["agent_name"])

    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )

    # If budget was exhausted while a task was in-progress, save whatever partial
    # work the model produced so it appears in the investigation summary.
    current_task = state.get("current_task")
    if over_budget and current_task and state["agent_name"] == "investigation":
        complete_fn = tmap.get("complete_task")
        if complete_fn:
            partial = ""
            for msg in reversed(state.get("messages", [])):
                content = getattr(msg, "content", "")
                if content and getattr(msg, "type", "") == "ai":
                    partial = content.strip()
                    break
            note = (
                "[Budget exhausted — partial findings]\n\n" + partial
                if partial else
                "[Budget exhausted — no findings recorded for this task]"
            )
            await _call(complete_fn, {"task_id": current_task["id"], "summary": note[:600]})
            emit(src, "note",
                 f"budget: saved partial work for "
                 f"'{(current_task.get('title') or current_task['id'])[:60]}'")

    # Build a structured investigation summary so the orchestrator and analyst
    # always receive complete findings, not just the last task's answer.
    if state["agent_name"] == "investigation":
        final_answer = await _build_investigation_summary(
            state, tmap, config["configurable"].get("model")
        )
    else:
        final_answer = state.get("final_answer") or f"{state['agent_name']} complete."

    write_fn = tmap.get("write")
    if write_fn and state["agent_name"] != "triage":
        path = f"{reports_dir(state['case_id'])}/final.md"

        async def call_tool(name: str, args: dict) -> str:
            fn = tmap.get(name)
            if fn is None:
                return f"Error: tool '{name}' is not available"
            return await _call(fn, args)

        await write_file(
            call_tool=call_tool,
            path=path,
            content=final_answer,
            created_by=state["agent_name"],
            summary="Final investigation report.",
        )

    status = "incomplete_budget" if over_budget else "completed"
    emit(src, "done",
         f"{status} (steps={state['steps']}/{state['max_steps']}, "
         f"calls={state['tool_calls_made']}/{state['max_tool_calls']})")
    return {
        "status": status,
        "final_answer": final_answer,
    }


def _route_claim(state: AgentState) -> str:
    return "intent" if state.get("current_task") else "finish"


def _route_intent(state: AgentState) -> str:
    return "finish" if state.get("status") == "cancelled" else "think"


def _route_use_tools(state: AgentState) -> str:
    if state.get("status") == "cancelled":
        return "finish"
    return "intent"


def _route_think(state: AgentState) -> str:
    if state["steps"] >= state["max_steps"] or state["tool_calls_made"] >= state["max_tool_calls"]:
        return "finish"
    last = state["messages"][-1] if state["messages"] else None
    return "use_tools" if (last and getattr(last, "tool_calls", None)) else "assess"


def _route_assess(state: AgentState) -> str:
    if state["steps"] >= state["max_steps"] or state["tool_calls_made"] >= state["max_tool_calls"]:
        return "finish"
    if state.get("status") == "_seed_retry":
        return "intent"
    return "pivot"


def build_graph():
    g = StateGraph(AgentState)
    g.add_node("seed", seed)
    g.add_node("claim", claim)
    g.add_node("intent", intent)
    g.add_node("think", think)
    g.add_node("use_tools", use_tools)
    g.add_node("assess", assess)
    g.add_node("pivot", pivot)
    g.add_node("finish", finish)

    g.set_entry_point("seed")
    g.add_edge("seed", "claim")
    g.add_conditional_edges("claim", _route_claim, {"intent": "intent", "finish": "finish"})
    g.add_conditional_edges("intent", _route_intent, {"think": "think", "finish": "finish"})
    g.add_conditional_edges("use_tools", _route_use_tools, {"intent": "intent", "finish": "finish"})
    g.add_conditional_edges(
        "think",
        _route_think,
        {"use_tools": "use_tools", "assess": "assess", "finish": "finish"},
    )
    g.add_conditional_edges(
        "assess", _route_assess,
        {"pivot": "pivot", "intent": "intent", "finish": "finish"},
    )
    g.add_edge("pivot", "claim")
    g.add_edge("finish", END)
    return g.compile()


GRAPH = build_graph()


async def _cancel_requested(run_id: str) -> bool:
    try:
        from ..models import AgentRun

        run = await AgentRun.objects.aget(id=run_id)
        return run.status == AgentRun.STATUS_CANCELLED or bool((run.metadata or {}).get("cancel_requested"))
    except Exception:
        return False
