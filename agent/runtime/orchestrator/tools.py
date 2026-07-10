from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Annotated, Optional

log = logging.getLogger(__name__)

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import Field

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
from .specialist_sync import apply_specialist_run_to_session, propagate_verdict_to_current_session


def _has_completed_triage_handoff(session: OrchestratorSession, src_entity_id: str) -> bool:
    """True only when the session holds a completed triage report for this entity."""
    return (
        session.last_triage_src_entity_id == src_entity_id
        and session.last_triage_status == AgentRun.STATUS_COMPLETED
        and bool((session.last_triage_report or "").strip())
    )



async def _propagate_verdict_to_session(verdict: dict | None) -> None:
    """Compatibility wrapper; canonical session publication lives in specialist_sync."""
    await propagate_verdict_to_current_session(verdict, current_session_id=current_session())


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


_SrcEntityId = Annotated[str, Field(description=(
    "The primary case/alert/event identifier from the analyst's request (e.g. "
    "'~449101824'). This may be a SOAR case id, a standalone SOAR alert id, or a "
    "SIEM-side alert/event reference — pass through whatever identifier was given "
    "as-is; do not classify or reformat it (beyond preserving any existing '~' "
    "prefix). The target agent determines which kind of identifier it is and "
    "resolves it accordingly."
))]


def _make_agent_tool(session: OrchestratorSession, agent_def: AgentDefinition) -> StructuredTool:
    name = agent_def.name

    def _resolved_source_entity_type(src_entity_id: str, question: str) -> str:
        if session.src_entity_id == src_entity_id and session.source_entity_type:
            return session.source_entity_type
        text = (question or "").lower()
        if "alert" in text:
            return "alert"
        if "case" in text:
            return "case"
        return "unknown"

    async def _execute(
        src_entity_id: str,
        question: str,
        triage_report: Optional[str],
        prior_investigation_report: Optional[str] = None,
    ) -> str:
        # Normalise bare numeric ids only. Opaque TheHive alert ids are valid
        # as-is, and alert-anchored benchmark sessions may have no case yet.
        src_entity_id = src_entity_id.strip() if isinstance(src_entity_id, str) else ""
        if src_entity_id and src_entity_id.isdigit():
            src_entity_id = f"~{src_entity_id}"
        session.src_entity_id = src_entity_id
        source_entity_type = _resolved_source_entity_type(src_entity_id, question)
        if source_entity_type != "unknown":
            session.source_entity_type = source_entity_type

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
            # Resume mode: prior investigation ran out of budget; use its report
            # to seed a new investigation focused on the remaining open gaps.
            resume_report = prior_investigation_report or (
                session.last_investigation_report
                if session.last_investigation_status == "incomplete_budget"
                   and session.last_triage_src_entity_id == src_entity_id
                else None
            )
            if resume_report:
                handoff = Handoff(
                    analyst_request=question,
                    source_run_id=session.last_triage_run_id or "",
                    source_entity_id=src_entity_id,
                    source_entity_type=source_entity_type,
                    prior_investigation_report=resume_report,
                )
                emit("orch", "note", "investigation: resume mode — seeding from prior run's open gaps")
            else:
                stored_report = (
                    session.last_triage_report
                    if _has_completed_triage_handoff(session, src_entity_id) else None
                )
                report = stored_report or triage_report
                if report:
                    handoff = Handoff(
                        analyst_request=question,
                        triage_report=report,
                        source_run_id=session.last_triage_run_id or "",
                        source_entity_id=src_entity_id,
                        source_entity_type=source_entity_type,
                    )

        emit("orch", "route", f"{name}(entity={src_entity_id})", detail=f"handoff={'yes' if handoff else 'no'}")
        run = await dispatch_run(
            name, src_entity_id, question,
            session_id=current_session(),
            trigger=AgentRun.TRIGGER_INTERACTIVE,
            handoff=handoff,
            orchestrator_context=convo_text or None,
            metadata={
                "source_entity_id": src_entity_id,
                "source_entity_type": source_entity_type,
            },
        )

        # produces_handoff agents (triage) leave a report the orchestrator captures
        # for the next investigation call and a checkpoint prompt to the analyst.
        if agent_def.produces_handoff or agent_def.consumes_handoff:
            apply_specialist_run_to_session(session, run)
            if agent_def.produces_handoff:
                session.investigation_run_id = None
                session.last_investigation_status = None  # reset resume state for new case
            # Dashboard verdict totals count session rows, not interactive child runs.
            await propagate_verdict_to_current_session(
                run.verdict,
                current_session_id=current_session(),
            )

        return _agent_run_summary(agent_def, run)

    # Only handoff-consuming agents expose the triage/resume report parameters,
    # so the tool schema matches what each agent actually accepts.
    if agent_def.consumes_handoff:
        async def _run(
            src_entity_id: _SrcEntityId,
            question: str,
            triage_report: Optional[str] = None,
            prior_investigation_report: Optional[str] = None,
        ) -> str:
            return await _execute(src_entity_id, question, triage_report, prior_investigation_report)
    else:
        async def _run(src_entity_id: _SrcEntityId, question: str) -> str:
            return await _execute(src_entity_id, question, None)

    _run.__doc__ = agent_def.description
    return StructuredTool.from_function(
        coroutine=_run, name=name, description=agent_def.description
    )


def _agent_run_summary(agent_def: AgentDefinition, run: AgentRun) -> str:
    issues = _format_subagent_issues(str(run.id))
    if agent_def.produces_handoff:
        triage_report = (
            (run.result or "")[:6000]
            if run.status == AgentRun.STATUS_COMPLETED and (run.result or "").strip()
            else "(unavailable: triage did not complete with a durable report)"
        )
        return (
            f"{agent_def.name} status={run.status}; error={run.error or 'none'}; "
            f"verdict={((run.verdict or {}).get('verdict') if isinstance(run.verdict, dict) else 'missing')}; "
            f"triage_report={triage_report}\n\n"
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
