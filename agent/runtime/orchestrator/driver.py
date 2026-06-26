from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool

from ...agents.base import AgentDefinition, Handoff
from ...agents.registry import get_agent, list_agents
from ...models import AgentRun
from ..infra.avfs import reports_dir
from ..engine.dispatch import dispatch_run
from ..graph import (
    _compact_history, _extract_input_tokens, _invoke_bound_model, _normalize,
    _sanitize_history, _sanitize_message, _should_compact, _tmap,
)
from ..analysis.intent import generate_public_intent
from ..infra.logbus import (
    current_session, emit, get_run_issues, summarize_args, summarize_result,
    summarize_think, update_context_usage,
)
from ..engine.mcp_client import build_mcp_client, load_mcp_prompt_guidance
from ..engine.model_client import build_model
from ..config.prompts import compose_system_prompt

from .messages import _append_visible
from .prompts import _ORCHESTRATOR_TOOL_POLICY, _orchestrator_system_prompt
from .session import OrchestratorSession
from .tools import _make_tools



_INV_NEG_RE = re.compile(
    r"(?:don'?t|do\s+not|without|no)\s+invest",
    re.IGNORECASE,
)
_INV_TRIAGE_ONLY_RE = re.compile(
    r"\btriage[\s,]+only\b|\bonly[\s,]+triage\b",
    re.IGNORECASE,
)
_INV_INQUIRY_RE = re.compile(
    r"\bwhether\b|\bwarrant|\bworth\s+invest"
    r"|\bshould\s+(?:we|i)\s+invest"
    r"|\bdo\s+we\s+need\b"
    r"|\bdecide\s+if\b"
    r"|\btell\s+me\s+(?:if|whether)\b"
    r"|\bis\s+this\s+worth\b",
    re.IGNORECASE,
)
_INV_IMPERATIVE_RE = re.compile(
    r"\binvestigate\b|\binvestigation\b",
    re.IGNORECASE,
)
# Short affirmative consent messages the analyst sends after reading the triage report.
# Only used when a stored triage report exists and no investigation has started yet.
_INV_CONSENT_RE = re.compile(
    r"^\s*(?:yes|y|yep|yeah|ok|okay|sure|go|go\s+ahead|proceed|continue|start|"
    r"do\s+it|run\s+it|let'?s\s+go|sounds\s+good|agreed|affirmative)\s*[!.]?\s*$",
    re.IGNORECASE,
)

# Matches triage requests: explicit "triage", case-inquiry phrases, or case IDs
# paired with incident-analysis verbs.
_TRIAGE_EXPLICIT_RE = re.compile(r"\btriage\b", re.IGNORECASE)
_TRIAGE_CASE_INQUIRY_RE = re.compile(
    r"\bwhat\s+happened\b|\btell\s+me\s+about\s+case\b"
    r"|\banalyze\s+case\b|\banalyse\s+case\b"
    r"|\bwhat\s+is\s+case\b|\bwhat.s\s+in\s+case\b"
    r"|\bsummariz[e]?\s+case\b|\bsummary\s+of\s+case\b",
    re.IGNORECASE,
)
# Extracts the first TheHive case ID (~digits or bare digits) from a string.
_CASE_ID_RE = re.compile(r"(~\d+|\b\d{7,}\b)")


def _extract_triage_case_id(question: str, session_case_id: str | None) -> str | None:
    """Return a case ID if the question is a triage request, else None.

    Does not match opt-outs ("triage only" is fine, "don't triage" is not).
    """
    if not question:
        return None
    q = question.strip()
    # Is it a triage request?
    is_triage = _TRIAGE_EXPLICIT_RE.search(q) or _TRIAGE_CASE_INQUIRY_RE.search(q)
    if not is_triage:
        return None
    # Extract case ID from question or fall back to session context.
    m = _CASE_ID_RE.search(q)
    if m:
        raw = m.group(1)
        return raw if raw.startswith("~") else f"~{raw}"
    if session_case_id:
        return session_case_id
    return None


def _analyst_requested_investigation(question: str | None) -> bool:
    """Return True only when the analyst explicitly commands investigation.

    Inquiries ("does this warrant investigation?") and opt-outs ("triage only")
    return False so the orchestrator does not bypass the analyst checkpoint.
    """
    if not question:
        return False
    q = question.strip()
    if not q:
        return False
    if _INV_NEG_RE.search(q) or _INV_TRIAGE_ONLY_RE.search(q):
        return False
    if _INV_INQUIRY_RE.search(q):
        return False
    return bool(_INV_IMPERATIVE_RE.search(q))


async def run_orchestrator(session: OrchestratorSession, question: str, max_rounds: int = 12) -> str:
    """Handle one analyst question, maintaining conversation history across calls."""
    try:
        return await _run_orchestrator_impl(session, question, max_rounds)
    finally:
        # On cancellation or exception, always save the current conversation state
        # so the analyst can resume or ask a follow-up without losing context.
        pass  # session.messages is saved inside _run_orchestrator_impl before each return


def _format_triage_answer(session: OrchestratorSession) -> str:
    report = (session.last_triage_report or "").strip()
    verdict = session.last_triage_verdict if isinstance(session.last_triage_verdict, dict) else None
    if not verdict:
        prefix = (
            "Triage completed, but it did not produce a valid structured verdict. "
            "Do not treat the prose report as a durable TP/FP diagnosis."
        )
        return prefix + (f"\n\n{report}" if report else "")
    verdict_label = (verdict.get("verdict") or "unknown").upper()
    confidence = verdict.get("confidence") or "?"
    prefix = f"Triage complete. Structured verdict: {verdict_label} (confidence: {confidence})."
    return prefix + (f"\n\n{report}" if report else "")


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
    model = await build_model()

    # Gate case-write tools: only expose them when the analyst's message
    # contains an explicit write directive. Without this gate the model follows
    # MCP server instructions and posts reports after every investigation.
    _CASE_WRITE_TOOLS = frozenset({
        "post_case_report", "update_case", "close_case",
        "resolve_case", "add_case_comment", "post_case_comment",
    })
    _WRITE_PHRASES = re.compile(
        r"\b(post|write|submit|send|publish|add|create)\b.{0,40}"
        r"\b(report|page|comment|note|findings?)\b"
        r"|\b(close|resolve|update)\b.{0,20}\bcase\b"
        r"|\bwrite to the case\b",
        re.IGNORECASE,
    )
    write_authorized = bool(_WRITE_PHRASES.search(question))
    if not write_authorized:
        tools_for_model = [t for t in tools if getattr(t, "name", "") not in _CASE_WRITE_TOOLS]
    else:
        tools_for_model = tools
    bound = model.bind_tools(tools_for_model)

    # Build from existing history (multi-turn) or start fresh, with updated system prompt.
    sys_msg = SystemMessage(content=_orchestrator_system_prompt(session, tool_names, mcp_prompt_guidance))
    if session.messages:
        prior = [m for m in session.messages if not isinstance(m, SystemMessage)]
        messages = [sys_msg] + prior + [HumanMessage(content=question)]
    else:
        messages = [sys_msg, HumanMessage(content=question)]
    _append_visible(session.visible_transcript, "user", question)

    # Inject a hard routing directive when the question is a triage request and
    # triage has not already run this session.  This overrides the intent model's
    # tendency to answer case-inquiry questions with inline raw-tool calls.
    triage_case_id = _extract_triage_case_id(question, session.case_id)
    if triage_case_id and not session.last_triage_report and "triage" in tmap:
        directive = (
            f"[Routing directive — follow exactly] "
            f"The analyst's message is a triage request for case {triage_case_id}. "
            f"Your FIRST and ONLY correct action is to call the `triage` tool with "
            f"case_id='{triage_case_id}'. Do NOT call get_case, list_case_alerts, "
            f"search_keyword, profile_field, top_field_values, get_event, get_alert, "
            f"or any other data-source tool before `triage` completes."
        )
        messages.append(HumanMessage(content=directive))
        emit("orch", "note", f"routing directive: triage({triage_case_id})")

    # Inject a hard routing directive when the analyst confirms investigation after triage.
    # Fires when: (1) a triage report is stored, (2) no investigation has started,
    # and (3) the analyst's message is a short affirmative consent or an explicit
    # investigation request.  Prevents the orchestrator from re-doing the work itself
    # using raw data-source tools instead of delegating to the investigation sub-agent.
    is_investigation_consent = (
        bool(session.last_triage_report)
        and not session.investigation_run_id
        and "investigation" in tmap
        and (
            _analyst_requested_investigation(question)
            or bool(_INV_CONSENT_RE.match(question))
        )
    )
    if is_investigation_consent:
        inv_case_id = session.last_triage_case_id or session.case_id or ""
        directive = (
            f"[Routing directive — follow exactly] "
            f"The analyst has confirmed investigation for case {inv_case_id}. "
            f"Your FIRST and ONLY correct action is to call the `investigation` tool with "
            f"case_id='{inv_case_id}', question='Investigate case {inv_case_id}', "
            f"and the stored triage report as `triage_report`. "
            f"Do NOT call get_case, list_case_alerts, search, search_keyword, get_alert, "
            f"get_event, or any other data-source tool directly — those are for the "
            f"investigation sub-agent to use, not for you."
        )
        messages.append(HumanMessage(content=directive))
        emit("orch", "note", f"routing directive: investigation({inv_case_id})")

    # Resume directive: fires when a prior investigation ran out of budget and the
    # analyst sends a consent-like message ("continue", "yes", "go ahead", etc.).
    # The investigation tool receives prior_investigation_report so the seed step
    # creates tasks only for the remaining open gaps.
    is_investigation_resume = (
        bool(session.last_investigation_report)
        and session.last_investigation_status == "incomplete_budget"
        and "investigation" in tmap
        and bool(_INV_CONSENT_RE.match(question))
        and not is_investigation_consent  # don't fire both directives
    )
    if is_investigation_resume:
        resume_case_id = session.case_id or ""
        directive = (
            f"[Routing directive — follow exactly] "
            f"The prior investigation for case {resume_case_id} ran out of budget. "
            f"The analyst wants to continue from where it left off. "
            f"Your FIRST and ONLY correct action is to call the `investigation` tool with "
            f"case_id='{resume_case_id}', question='Continue investigation of case {resume_case_id}', "
            f"and the stored prior investigation report as `prior_investigation_report`. "
            f"Do NOT call any data-source tools directly — those are for the "
            f"investigation sub-agent to use, not for you."
        )
        messages.append(HumanMessage(content=directive))
        emit("orch", "note", f"routing directive: investigation resume({resume_case_id})")

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
                "Perform that action now. Return tool calls to execute the planned "
                "action. Only respond with text when all tool calls are complete and "
                "you have results to report to the analyst."
            )))

        session.thinking = True
        try:
            messages = _sanitize_history(messages)
            call_messages = messages
            if call_messages and isinstance(call_messages[-1], ToolMessage):
                call_messages = call_messages + [HumanMessage(content=(
                    "Tool results received. Continue your investigation: make more tool calls "
                    "to gather additional data, or write your findings as plain text if you "
                    "have enough to answer the analyst's question."
                ))]
            response = await _invoke_bound_model(bound, call_messages, "orchestrator")
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
                _append_visible(session.visible_transcript, "assistant", text)
                return text
            # Empty response (harmony tokens stripped to nothing) — retry once
            # with a text-only model and an explicit instruction.
            emit("orch", "note", "empty response — retrying with text-only model")
            text_only_bound = await build_model()
            session.thinking = True
            try:
                retry_msgs = _sanitize_history(
                    messages + [HumanMessage(content=(
                        "Write your response to the analyst as plain text now. "
                        "Use the tool results above to answer their question directly. "
                        "Do not call any tools. State what you found and your conclusion."
                    ))]
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
                # Use retry text, or fall back to the public intent summary which
                # already captured what the model was about to say.
                answer = retry_text or current_intent or "(no answer)"
                _append_visible(session.visible_transcript, "assistant", answer)
                return answer
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
                raw_cid = args["case_id"]
                # TheHive case IDs require the ~ prefix; normalise bare numerics.
                session.case_id = raw_cid if raw_cid.startswith("~") else f"~{raw_cid}"
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

        # Auto-trigger investigation when triage just completed AND the analyst
        # explicitly requested investigation in the original question.
        # This prevents the model from returning the triage report prematurely
        # instead of following through on the analyst's request.
        if (produces_handoff_ran and session.last_triage_report
                and _analyst_requested_investigation(question)):
            invest_tool = tmap.get("investigation")
            if invest_tool is not None:
                emit("orch", "note", "auto-triggering investigation per analyst request")
                invest_args = {
                    "case_id": session.case_id or "",
                    "question": question,
                    "triage_report": session.last_triage_report,
                }
                emit("orch", "call",
                     f"investigation({summarize_args(invest_args)})",
                     detail=json.dumps(invest_args, indent=2, default=str))
                try:
                    inv_content = await invest_tool.ainvoke(invest_args)
                    if not isinstance(inv_content, str):
                        inv_content = _normalize(inv_content)
                    emit("orch", "result",
                         f"investigation: {summarize_result('investigation', inv_content)}",
                         detail=inv_content)
                except asyncio.CancelledError:
                    raise
                # Do NOT append a ToolMessage — there is no matching tool_call_id in the
                # preceding AIMessage, so the OpenAI API rejects it on history replay.
                # The result is captured in session.last_investigation_report by the tool;
                # add it as a HumanMessage so the text-only fallback can reference it too.
                messages.append(HumanMessage(content=f"[investigation result]\n{inv_content}"))
                produces_handoff_ran = False
                consumes_handoff_ran = True

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
            # Store only a compact summary in the visible_transcript so the system
            # prompt stays bounded on follow-up turns. The full report is preserved
            # in session.last_investigation_report for explicit retrieval.
            _TRANSCRIPT_REPORT_LIMIT = 3000
            report_text = session.last_investigation_report.strip()
            if len(report_text) > _TRANSCRIPT_REPORT_LIMIT:
                transcript_entry = (
                    "The investigation is complete. Full report below:\n\n"
                    + report_text[:_TRANSCRIPT_REPORT_LIMIT]
                    + f"\n\n...[report truncated for context management — full report is in session.last_investigation_report and the case system]"
                )
            else:
                transcript_entry = answer
            _append_visible(session.visible_transcript, "assistant", transcript_entry)
            return answer

        # Triage: use the persisted structured verdict if one exists; otherwise
        # explicitly report that the specialist failed to produce a valid contract.
        if produces_handoff_ran and (session.last_triage_report or "").strip():
            answer = _format_triage_answer(session)
            messages.append(AIMessage(content=answer))
            session.messages = messages
            _append_visible(session.visible_transcript, "assistant", answer)
            return answer

        # Triage (or investigation with an empty report): force one text-only model
        # call to present the result and to avoid the small model looping or emitting
        # an empty response when harmony tokens are stripped.
        if produces_handoff_ran or consumes_handoff_ran:
            text_only_bound = await build_model()  # not bound to any tools
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
            answer = (final_response.content or "").strip() or fallback
            _append_visible(session.visible_transcript, "assistant", answer)
            return answer

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
    answer = (final.content or "").strip() or "(no answer)"
    _append_visible(session.visible_transcript, "assistant", answer)
    return answer

