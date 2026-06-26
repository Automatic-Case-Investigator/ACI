from __future__ import annotations

"""Entry points for executing a single triage or investigation agent run."""

import asyncio
import logging

from django.conf import settings

from ...agents.registry import get_agent
from ...models import AgentRun
from ..infra.avfs import case_dir, home_dir, memory_dir
from ..graph import GRAPH, AgentState
from ..infra.logbus import (
    bind_debug_mode, bind_run, bind_session, clear_run_issues, current_session,
    emit, reset_debug_mode, reset_run, reset_session, src_label,
)
from .mcp_client import build_mcp_client, load_mcp_prompt_guidance
from .model_client import build_model
from ..config.prompts import compose_system_prompt

log = logging.getLogger(__name__)


def _prompt_tool_names(agent_name: str, tools: list) -> list[str]:
    """Filter tool names exposed in prompts when an agent should not advertise all tools."""
    if agent_name == "triage":
        return [tool.name for tool in tools if tool.name != "create_task"]
    return [tool.name for tool in tools]


async def run_agent(
    run_id: str,
    agent_name: str,
    case_id: str,
    question: str,
) -> None:
    """Run one agent while binding log/session context for dashboard streaming."""
    # Tag every event from this run with the specific AgentRun id (dashboard display).
    clear_run_issues(run_id)
    session_token = bind_session(run_id) if current_session() is None else None
    run_token = bind_run(run_id)
    from ..config.runtime_config import debug_mode as _debug_mode
    debug_token = bind_debug_mode(_debug_mode())
    try:
        await _run_agent_bound(run_id, agent_name, case_id, question)
    finally:
        reset_debug_mode(debug_token)
        reset_run(run_token)
        if session_token is not None:
            reset_session(session_token)


async def _run_agent_bound(
    run_id: str,
    agent_name: str,
    case_id: str,
    question: str,
) -> None:
    """Resolve runtime dependencies, invoke the graph, and persist the final result."""
    agent_def = get_agent(agent_name)
    if agent_def is None:
        raise ValueError(f"Unknown agent: {agent_name}")
    # Apply analyst-editable budget / tool-policy overrides from the settings UI.
    from asgiref.sync import sync_to_async
    from ..config.overrides import resolve_agent_definition
    agent_def = await sync_to_async(resolve_agent_definition, thread_sensitive=True)(agent_def)

    run = await AgentRun.objects.aget(id=run_id)
    run.status = AgentRun.STATUS_RUNNING
    await run.asave(update_fields=["status", "updated_at"])

    # A structured handoff (e.g. triage → investigation) travels in metadata so the
    # graph's seed step can build the queue from explicit fields, not string-matching.
    handoff = (run.metadata or {}).get("handoff")
    restart_context = (run.metadata or {}).get("restart_context")
    # Prior analyst conversation embedded by the orchestrator (interactive runs only).
    orchestrator_conversation = (run.metadata or {}).get("orchestrator_context")

    try:
        mcp = await build_mcp_client(
            agent_def.tool_policy,
            run_ctx={"case_id": case_id, "run_id": run_id, "agent_name": agent_name},
        )
        mcp_prompt_guidance = await load_mcp_prompt_guidance(mcp)
        tools = await mcp.get_tools()
        model = await build_model()
        system_prompt = compose_system_prompt(
            agent_def.prompt_layers,
            {
                "case_id": case_id,
                "run_id": run_id,
                "agent_name": agent_name,
                "budget": {
                    "max_steps": agent_def.budget.max_steps,
                    "max_tool_calls": agent_def.budget.max_tool_calls,
                },
                "default_vicinity_window_hours": agent_def.default_vicinity_window_hours,
                "avfs_home": home_dir(),
                "avfs_memory_dir": memory_dir(),
                "avfs_case_dir": case_dir(case_id),
                "available_tools": _prompt_tool_names(agent_name, tools),
                "mcp_prompt_guidance": mcp_prompt_guidance,
                "orchestrator_conversation": orchestrator_conversation,
                "restart_context": restart_context,
            },
        )

        initial_state = AgentState(
            run_id=run_id,
            case_id=case_id,
            agent_name=agent_name,
            question=question,
            handoff=handoff,
            current_task=None,
            messages=[],
            steps=0,
            tool_calls_made=0,
            max_steps=agent_def.budget.max_steps,
            max_tool_calls=agent_def.budget.max_tool_calls,
            default_vicinity_window_hours=agent_def.default_vicinity_window_hours,
            status="running",
            final_answer="",
            ctx_tokens=0,
            verdict=None,
            pivot_tasks_created=0,
            summary_format_retries=0,
        )

        config = {
            "configurable": {
                "model": model,
                "tools": tools,
                "system_prompt": system_prompt,
            },
            # LangGraph's default recursion limit is 25 graph transitions, which is
            # lower than our agent budgets once a task needs multiple tool calls.
            "recursion_limit": max(
                50,
                (agent_def.budget.max_steps + agent_def.budget.max_tool_calls) * 3,
            ),
        }

        final_state = await GRAPH.ainvoke(initial_state, config=config)

        run.status = final_state.get("status", AgentRun.STATUS_COMPLETED)
        run.result = final_state.get("final_answer", "")
        run.verdict = final_state.get("verdict")
        await run.asave(update_fields=["status", "result", "verdict", "updated_at"])

    except Exception as exc:
        log.exception("Agent run %s failed", run_id)
        emit(src_label(agent_name), "error", f"agent run failed: {exc}", detail=str(exc))
        try:
            run.status = AgentRun.STATUS_FAILED
            run.error = str(exc)
            await run.asave(update_fields=["status", "error", "updated_at"])
        except Exception:
            pass


def run_agent_sync(
    run_id: str,
    agent_name: str,
    case_id: str,
    question: str,
) -> None:
    """Synchronous wrapper used by Django management commands and worker entry points."""
    asyncio.run(run_agent(run_id, agent_name, case_id, question))
