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
from .messages import _summarize_conversation, render_conversation
from .prompts import _embedded_convo_char_budget
from .session import OrchestratorSession



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


async def _propagate_verdict_to_session(verdict: dict | None) -> None:
    """Copy a durable specialist verdict onto the session row counted by dashboard stats."""
    if not isinstance(verdict, dict):
        return
    session_run_id = current_session()
    if not session_run_id:
        return
    try:
        session_run = await AgentRun.objects.aget(id=session_run_id)
        session_run.verdict = verdict
        await session_run.asave(update_fields=["verdict", "updated_at"])
    except Exception as exc:
        log.warning("Could not propagate verdict to session %s: %s", session_run_id, exc)


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
        # Normalise bare numeric IDs — TheHive requires the ~ prefix.
        case_id = case_id if case_id.startswith("~") else f"~{case_id}"
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

        # consumes_handoff agents (investigation) accept an explicit triage report.
        # Always prefer the session-stored full triage report (set when triage
        # completed) over the LLM-supplied parameter, which may be truncated or
        # summarized from the model's context. The LLM-supplied value is only used
        # when there is no session-stored report for the requested case.
        handoff = None
        if agent_def.consumes_handoff:
            stored_report = (
                session.last_triage_report
                if session.last_triage_case_id == case_id else None
            )
            report = stored_report or triage_report
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
            session.last_triage_verdict = run.verdict if isinstance(run.verdict, dict) else None
            session.investigation_run_id = None
            await _propagate_verdict_to_session(run.verdict)
        if agent_def.consumes_handoff:
            session.investigation_run_id = str(run.id)
            # Keep the FULL investigation report so the orchestrator can deliver it
            # verbatim to the analyst (the in-context tool summary below is truncated).
            session.last_investigation_report = run.result or ""
            # Dashboard verdict totals count session rows, not interactive child runs.
            await _propagate_verdict_to_session(run.verdict)

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
            f"verdict={((run.verdict or {}).get('verdict') if isinstance(run.verdict, dict) else 'missing')}; "
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
    result_limit = 16000 if agent_def.consumes_handoff else 1500
    return (
        f"{agent_def.name} status={run.status}; error={run.error or 'none'}; "
        f"result={(run.result or '')[:result_limit]}; "
        f"subagent_warnings_errors:\n{issues}{tail}"
    )

