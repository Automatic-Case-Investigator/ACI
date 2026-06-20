"""Meta-agent orchestrator.

An LLM that receives the analyst's question and routes it to the triage or
investigation agent, which are exposed to it as callable tools. It is a small
async think -> tool_call -> observe loop (no LangGraph), reusing the message
handling and harmony-token stripping from `graph.py`.
"""
from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool

from ..agents.base import AgentDefinition, Handoff
from ..agents.registry import get_agent, list_agents
from ..models import AgentRun
from .avfs import reports_dir
from .dispatch import dispatch_run
from .graph import (
    _compact_history, _extract_input_tokens, _invoke_bound_model, _normalize,
    _sanitize_history, _sanitize_message, _should_compact, _tmap,
)
from .intent import generate_public_intent
from .logbus import (
    current_session, emit, get_run_issues, summarize_args, summarize_result,
    summarize_think, update_context_usage,
)
from .mcp_client import build_mcp_client, load_mcp_prompt_guidance
from .model_client import build_model
from .prompts import compose_system_prompt


def _serialize_messages(messages: list) -> list[dict]:
    """Convert LangChain message objects to plain JSON-safe dicts."""
    out = []
    for msg in messages:
        t = getattr(msg, "type", None)
        c = getattr(msg, "content", "")
        if t == "human":
            out.append({"type": "human", "content": c})
        elif t == "system":
            out.append({"type": "system", "content": c})
        elif t == "ai":
            out.append({
                "type": "ai",
                "content": c,
                "tool_calls": getattr(msg, "tool_calls", []) or [],
                "additional_kwargs": dict(getattr(msg, "additional_kwargs", {}) or {}),
            })
        elif t == "tool":
            out.append({
                "type": "tool",
                "content": c,
                "tool_call_id": getattr(msg, "tool_call_id", "") or "",
                "name": getattr(msg, "name", "") or "",
            })
    return out


def _deserialize_messages(data: list[dict]) -> list:
    """Restore LangChain message objects from serialized dicts."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    out = []
    for d in (data or []):
        t = d.get("type", "")
        c = d.get("content", "")
        try:
            if t == "human":
                out.append(HumanMessage(content=c))
            elif t == "system":
                out.append(SystemMessage(content=c))
            elif t == "ai":
                out.append(AIMessage(
                    content=c,
                    tool_calls=d.get("tool_calls") or [],
                    additional_kwargs=d.get("additional_kwargs") or {},
                ))
            elif t == "tool":
                out.append(ToolMessage(
                    content=c,
                    tool_call_id=d.get("tool_call_id", ""),
                    name=d.get("name", ""),
                ))
        except Exception:
            pass
    return out


def render_conversation(messages: list) -> str:
    """Render LangChain messages into a readable transcript for subagent context.

    Mirrors the type dispatch in `_serialize_messages`. System messages and the
    internal `[Public intent ...]` scaffold HumanMessages are skipped — they are
    orchestrator plumbing, not analyst dialogue.
    """
    lines: list[str] = []
    for msg in (messages or []):
        t = getattr(msg, "type", None)
        c = (getattr(msg, "content", "") or "")
        if not isinstance(c, str):
            c = str(c)
        c = c.strip()
        if t == "system":
            continue
        if t == "human":
            if c.startswith("[Public intent already shown to the analyst]"):
                continue
            if not c:
                continue
            lines.append(f"Analyst: {c}")
        elif t == "ai":
            if c:
                lines.append(f"Assistant: {c}")
        elif t == "tool":
            name = getattr(msg, "name", "") or "tool"
            if c:
                lines.append(f"[tool {name}] {c}")
    return "\n\n".join(lines)


async def _summarize_conversation(text: str) -> str:
    """Compact a long conversation transcript with one model call (overflow only).

    Reuses the summarization instruction wording from `graph._compact_history`.
    Returns the original text on any failure so the caller can continue.
    """
    try:
        model = build_model()
        resp = await model.ainvoke([
            HumanMessage(content=(
                "Concisely summarise the analyst conversation below. Preserve: case IDs, "
                "host names, IPs, key findings, tool results still relevant, and any "
                "context established so far. This replaces the prior history.\n\n"
                f"{text}"
            )),
        ])
        summary = (getattr(resp, "content", "") or "").strip()
        return summary or text
    except Exception:
        return text


@dataclass
class OrchestratorSession:
    """Shared state between the orchestrator and the dashboard for one analyst session."""
    case_id: Optional[str] = None
    investigation_run_id: Optional[str] = None
    last_triage_case_id: Optional[str] = None
    last_triage_report: Optional[str] = None
    last_triage_run_id: Optional[str] = None
    last_investigation_report: Optional[str] = None
    thinking: bool = False
    log_buffer: deque = field(default_factory=deque)
    messages: list = field(default_factory=list)
    ctx_tokens: int = 0  # input tokens from the most recent model call
    intent_sequence: int = 0
    model_calls_made: int = 0

    def to_state(self) -> dict:
        return {
            "case_id": self.case_id,
            "investigation_run_id": self.investigation_run_id,
            "last_triage_case_id": self.last_triage_case_id,
            "last_triage_report": self.last_triage_report,
            "last_triage_run_id": self.last_triage_run_id,
            "last_investigation_report": self.last_investigation_report,
            "ctx_tokens": self.ctx_tokens,
            "messages": _serialize_messages(self.messages),
            "intent_sequence": self.intent_sequence,
            "model_calls_made": self.model_calls_made,
        }

    def load_state(self, data: dict | None) -> None:
        if not data:
            return
        self.case_id = data.get("case_id", self.case_id)
        self.investigation_run_id = data.get("investigation_run_id", self.investigation_run_id)
        self.last_triage_case_id = data.get("last_triage_case_id", self.last_triage_case_id)
        self.last_triage_report = data.get("last_triage_report", self.last_triage_report)
        self.last_triage_run_id = data.get("last_triage_run_id", self.last_triage_run_id)
        self.last_investigation_report = data.get("last_investigation_report", self.last_investigation_report)
        self.ctx_tokens = data.get("ctx_tokens", self.ctx_tokens) or 0
        self.intent_sequence = data.get("intent_sequence", self.intent_sequence) or 0
        self.model_calls_made = data.get("model_calls_made", self.model_calls_made) or 0
        raw_msgs = data.get("messages")
        if raw_msgs:
            try:
                self.messages = _deserialize_messages(raw_msgs)
            except Exception:
                self.messages = []


def _format_subagent_issues(run_id: str) -> str:
    issues = get_run_issues(run_id)
    if not issues:
        return "none"
    lines: list[str] = []
    for issue in issues:
        detail = (issue.get("detail") or "").strip()
        if len(detail) > 1000:
            detail = detail[:1000] + "...[truncated]"
        lines.append(
            f"- [{issue.get('source')}/{issue.get('kind')}] "
            f"{issue.get('summary')}"
            + (f"\n  detail: {detail}" if detail else "")
        )
    return "\n".join(lines)


def _make_tools(session: OrchestratorSession) -> list[StructuredTool]:
    """Generate one orchestrator tool per routable agent in the registry (A2).

    A new agent becomes routable with zero edits here: register it with a
    description, and (optionally) `produces_handoff` / `consumes_handoff` so the
    triage→investigation handoff wiring applies automatically.
    """
    tools: list[StructuredTool] = []
    for name in list_agents():
        agent_def = get_agent(name)
        if agent_def is None or not agent_def.orchestrator_routable:
            continue
        tools.append(_make_agent_tool(session, agent_def))
    return tools


def _make_agent_tool(session: OrchestratorSession, agent_def: AgentDefinition) -> StructuredTool:
    name = agent_def.name

    async def _execute(case_id: str, question: str, triage_report: Optional[str]) -> str:
        session.case_id = case_id

        # Render the prior analyst conversation so the subagent shares the analyst's
        # established intent/scope. session.messages holds the previous turns (the
        # current request travels as `question`/`handoff`). Embed verbatim; summarize
        # with a single model call only if it exceeds the char budget.
        convo_text = render_conversation(session.messages)
        if convo_text and len(convo_text) > _embedded_convo_char_budget():
            emit("orch", "note",
                 f"compacting orchestrator conversation for handoff ({len(convo_text):,} chars)")
            convo_text = await _summarize_conversation(convo_text)
        if convo_text:
            emit("orch", "note",
                 f"embedded orchestrator conversation ({len(convo_text):,} chars) into {name}")

        # consumes_handoff agents (investigation) accept an explicit triage report,
        # falling back to the last triage captured this session for the same case.
        handoff = None
        if agent_def.consumes_handoff:
            report = triage_report or (
                session.last_triage_report
                if session.last_triage_case_id == case_id else None
            )
            if report:
                handoff = Handoff(
                    analyst_request=question,
                    triage_report=report,
                    source_run_id=session.last_triage_run_id or "",
                )

        emit("orch", "route", f"{name}(case={case_id})", detail=f"handoff={'yes' if handoff else 'no'}")
        run = await dispatch_run(
            name, case_id, question,
            session_id=current_session(),
            trigger=AgentRun.TRIGGER_INTERACTIVE,
            handoff=handoff,
            orchestrator_context=convo_text or None,
        )

        # produces_handoff agents (triage) leave a report the orchestrator captures
        # for the next investigation call and a checkpoint prompt to the analyst.
        if agent_def.produces_handoff:
            session.last_triage_case_id = case_id
            session.last_triage_report = run.result or ""
            session.last_triage_run_id = str(run.id)
            session.investigation_run_id = None
        if agent_def.consumes_handoff:
            session.investigation_run_id = str(run.id)
            # Keep the FULL investigation report so the orchestrator can deliver it
            # verbatim to the analyst (the in-context tool summary below is truncated).
            session.last_investigation_report = run.result or ""

        return _agent_run_summary(agent_def, run)

    # Only handoff-consuming agents expose the `triage_report` parameter, so the
    # tool schema matches what each agent actually accepts.
    if agent_def.consumes_handoff:
        async def _run(case_id: str, question: str, triage_report: Optional[str] = None) -> str:
            return await _execute(case_id, question, triage_report)
    else:
        async def _run(case_id: str, question: str) -> str:
            return await _execute(case_id, question, None)

    _run.__doc__ = agent_def.description
    return StructuredTool.from_function(
        coroutine=_run, name=name, description=agent_def.description
    )


def _agent_run_summary(agent_def: AgentDefinition, run: AgentRun) -> str:
    issues = _format_subagent_issues(str(run.id))
    if agent_def.produces_handoff:
        return (
            f"{agent_def.name} status={run.status}; error={run.error or 'none'}; "
            f"triage_report={(run.result or '')[:6000]}\n\n"
            f"subagent_warnings_errors:\n{issues}"
        )
    tail = (
        f"\nreport={reports_dir(run.case_id)}/final.md"
        if agent_def.consumes_handoff else ""
    )
    # Investigation summaries include confirmed facts, task summaries, and
    # incomplete tasks — they can be several KB. Send the full text so the
    # orchestrator can accurately report what was found and what was not done.
    result_limit = 8000 if agent_def.consumes_handoff else 1500
    return (
        f"{agent_def.name} status={run.status}; error={run.error or 'none'}; "
        f"result={(run.result or '')[:result_limit]}; "
        f"subagent_warnings_errors:\n{issues}{tail}"
    )


def _orchestrator_system_prompt(
    session: OrchestratorSession,
    tool_names: list[str] | None = None,
    mcp_prompt_guidance: str = "",
) -> str:
    return compose_system_prompt(
        ["platform", "orchestrator"],
        {
            "case_id": session.case_id or "none set yet — extract from the message or ask the analyst",
            "agent_name": "orchestrator",
            "available_tools": tool_names or [],
            "mcp_prompt_guidance": mcp_prompt_guidance,
        },
    )


_ORCHESTRATOR_TOOL_POLICY = ["aci-thehive", "aci-wazuh", "avfs"]


def _embedded_convo_char_budget() -> int:
    """Max chars of orchestrator transcript to embed verbatim in a subagent prompt.

    Bounded to ~30% of the context window (≈4 chars/token) so the subagent keeps
    room for its own work. Over this, the transcript is summarized before embedding.
    """
    try:
        from django.conf import settings
        limit = getattr(settings, "LLM_CONTEXT_LENGTH", 131072)
    except Exception:
        limit = 131072
    return int(limit * 0.30 * 4)


async def run_orchestrator(session: OrchestratorSession, question: str, max_rounds: int = 12) -> str:
    """Handle one analyst question, maintaining conversation history across calls."""
    try:
        return await _run_orchestrator_impl(session, question, max_rounds)
    finally:
        # On cancellation or exception, always save the current conversation state
        # so the analyst can resume or ask a follow-up without losing context.
        pass  # session.messages is saved inside _run_orchestrator_impl before each return


async def _run_orchestrator_impl(session: OrchestratorSession, question: str, max_rounds: int = 12) -> str:
    """Implementation of orchestrator with full state management."""
    # Load MCP tools (TheHive, Wazuh, AVFS) fresh per turn so the
    # subprocesses live within this event loop. Triage/investigation are added as
    # StructuredTools alongside them — the orchestrator chooses freely between all.
    mcp = await build_mcp_client(_ORCHESTRATOR_TOOL_POLICY)
    mcp_prompt_guidance = await load_mcp_prompt_guidance(mcp)
    mcp_tools = await mcp.get_tools()
    agent_tools = _make_tools(session)
    tools = mcp_tools + agent_tools
    tool_names = [t.name for t in tools]

    tmap = _tmap(tools)
    model = build_model()
    bound = model.bind_tools(tools)

    # Build from existing history (multi-turn) or start fresh, with updated system prompt.
    sys_msg = SystemMessage(content=_orchestrator_system_prompt(session, tool_names, mcp_prompt_guidance))
    if session.messages:
        prior = [m for m in session.messages if not isinstance(m, SystemMessage)]
        messages = [sys_msg] + prior + [HumanMessage(content=question)]
    else:
        messages = [sys_msg, HumanMessage(content=question)]

    for _ in range(max_rounds):
        if _should_compact(session.ctx_tokens):
            emit("orch", "note", f"context compaction triggered ({session.ctx_tokens:,} tokens)")
            messages = await _compact_history(messages, bound, "orchestrator")
            session.ctx_tokens = 0  # reset; updated from next response

        session.intent_sequence += 1
        intent_result = await generate_public_intent(
            model,
            _sanitize_history(messages),
            source="orch",
            sequence=session.intent_sequence,
            task_title=question,
            available_tools=tool_names,
        )
        session.model_calls_made += 1
        current_intent = intent_result.text
        if current_intent:
            messages.append(HumanMessage(content=(
                "[Public intent already shown to the analyst]\n"
                f"{current_intent}\n\n"
                "Perform that action now. Do not repeat the intent. Return tool calls "
                "when tools are needed, otherwise answer the analyst directly."
            )))

        session.thinking = True
        try:
            messages = _sanitize_history(messages)
            response = await _invoke_bound_model(bound, messages, "orchestrator")
        finally:
            session.thinking = False
        session.model_calls_made += 1
        _sanitize_message(response)
        t = _extract_input_tokens(response)
        if t:
            session.ctx_tokens = t
            update_context_usage(t, "orch")
        messages.append(response)

        text = (response.content or "").strip()
        tool_calls = getattr(response, "tool_calls", None)
        if text and tool_calls:
            emit("orch", "think", summarize_think(text), detail=text)

        if not tool_calls:
            if text:
                session.messages = messages
                return text
            # Empty response (harmony tokens stripped to nothing) — retry once
            # with a text-only model and an explicit instruction.
            emit("orch", "note", "empty response — retrying with text-only model")
            text_only_bound = build_model()
            session.thinking = True
            try:
                retry_msgs = _sanitize_history(
                    messages + [HumanMessage(content="Please provide your response as plain text.")]
                )
                retry_resp = await _invoke_bound_model(text_only_bound, retry_msgs, "orchestrator")
            finally:
                session.thinking = False
            _sanitize_message(retry_resp)
            t2 = _extract_input_tokens(retry_resp)
            if t2:
                session.ctx_tokens = t2
                update_context_usage(t2, "orch")
            messages.append(retry_resp)
            retry_text = (retry_resp.content or "").strip()
            retry_calls = getattr(retry_resp, "tool_calls", None)
            if not retry_calls:
                session.messages = messages
                return retry_text or "(no answer)"
            # Retry produced tool calls — fall through into normal tool execution
            # by replacing the variables the loop uses.
            response = retry_resp
            text = retry_text
            tool_calls = retry_calls

        produces_handoff_ran = False
        consumes_handoff_ran = False
        for tc in tool_calls:
            args = tc.get("args", {})
            # Track the case the analyst is working on so follow-up questions
            # don't lose context. Any tool that mentions a case_id (TheHive
            # lookups, sub-agent calls) updates the session.
            if not session.case_id and isinstance(args.get("case_id"), str) and args["case_id"]:
                session.case_id = args["case_id"]
            tool = tmap.get(tc["name"])
            if tool is None:
                available = ", ".join(sorted(tmap))
                content = (
                    f"Error: tool '{tc['name']}' does not exist. "
                    f"Available tools: {available}."
                )
                emit("orch", "error", f"unknown tool '{tc['name']}'", detail=content)
            else:
                emit("orch", "call", f"{tc['name']}({summarize_args(args)})",
                     detail=json.dumps(args, indent=2, default=str),
                     metadata=(
                         {"intent_sequence": session.intent_sequence}
                         if current_intent else {}
                     ))
                try:
                    content = await tool.ainvoke(tc["args"])
                    if not isinstance(content, str):
                        content = _normalize(content)
                    emit("orch", "result", f"{tc['name']}: {summarize_result(tc['name'], content)}", detail=content)
                except asyncio.CancelledError:
                    # Subagent was cancelled by the analyst (stop request). Record this state
                    # and save session before re-raising so follow-ups have context.
                    content = "[Tool execution cancelled by analyst]"
                    emit("orch", "result", f"{tc['name']}: [cancelled]", detail=content)
                    session.messages = messages
                    session.messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))
                    raise
                adef = get_agent(tc["name"])
                if adef is not None and adef.produces_handoff:
                    produces_handoff_ran = True
                if adef is not None and adef.consumes_handoff:
                    consumes_handoff_ran = True
            messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))

        # Investigation: deliver the full report VERBATIM. A model re-synthesis of a
        # (truncated) report silently drops confirmed findings, so the orchestrator
        # relays the investigation's own complete output instead of rewriting it.
        if consumes_handoff_ran and (session.last_investigation_report or "").strip():
            answer = (
                "The investigation is complete. Full report below:\n\n"
                + session.last_investigation_report.strip()
            )
            messages.append(AIMessage(content=answer))
            session.messages = messages
            return answer

        # Triage (or investigation with an empty report): force one text-only model
        # call to present the result and to avoid the small model looping or emitting
        # an empty response when harmony tokens are stripped.
        if produces_handoff_ran or consumes_handoff_ran:
            text_only_bound = build_model()  # not bound to any tools
            session.thinking = True
            try:
                agent_label = "Triage" if produces_handoff_ran else "Investigation"
                final_messages = _sanitize_history(
                    messages + [HumanMessage(content=(
                        f"{agent_label} is complete. Present the result from the tool result above "
                        "to the analyst. Write plain text only — no tool calls."
                    ))]
                )
                final_response = await _invoke_bound_model(text_only_bound, final_messages, "orchestrator")
            finally:
                session.thinking = False
            _sanitize_message(final_response)
            t = _extract_input_tokens(final_response)
            if t:
                session.ctx_tokens = t
                update_context_usage(t, "orch")
            messages.append(final_response)
            session.messages = messages
            # Triage fallback: return the captured triage report if the model emits nothing.
            # Investigation fallback: never substitute the triage report for an investigation summary.
            fallback = session.last_triage_report if produces_handoff_ran else "(no answer)"
            return (final_response.content or "").strip() or fallback

    # Budget exhausted — summarise work-so-far and yield with a resumable note (A4).
    emit("orch", "note", f"round budget reached ({max_rounds}) — ask a follow-up to continue",
         detail="resumable", expand=True)
    session.thinking = True
    try:
        final_messages = _sanitize_history(
            messages + [HumanMessage(content=(
                "You have reached the round budget for this turn. Summarise what was "
                "accomplished and what remains, in 2-3 sentences, so the analyst can "
                "continue with a follow-up."
            ))]
        )
        final = await _invoke_bound_model(bound, final_messages, "orchestrator")
    finally:
        session.thinking = False
    _sanitize_message(final)
    t = _extract_input_tokens(final)
    if t:
        session.ctx_tokens = t
        update_context_usage(t, "orch")
    messages.append(final)
    session.messages = messages
    return (final.content or "").strip() or "(no answer)"
