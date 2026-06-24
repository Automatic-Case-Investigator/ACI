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
from ..config.prompts import compose_system_prompt

from .session import OrchestratorSession



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
            "last_triage_report_available": bool((session.last_triage_report or "").strip()),
            "last_triage_case_id": session.last_triage_case_id or "",
            "investigation_run_id": session.investigation_run_id or "",
            "orchestrator_visible_transcript": session.visible_transcript,
        },
    )


_ORCHESTRATOR_TOOL_POLICY = ["aci-thehive", "aci-wazuh", "avfs"]


def _embedded_convo_char_budget() -> int:
    """Max chars of orchestrator transcript to embed verbatim in a subagent prompt.

    Bounded to ~30% of the context window (≈4 chars/token) so the subagent keeps
    room for its own work. Over this, the transcript is summarized before embedding.
    """
    try:
        from ..engine.model_client import model_context_length_sync
        limit = model_context_length_sync()
    except Exception:
        limit = 131072
    return int(limit * 0.30 * 4)

