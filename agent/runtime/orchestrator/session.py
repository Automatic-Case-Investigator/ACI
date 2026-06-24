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
from .messages import _deserialize_messages, _normalize_visible_transcript, _serialize_messages, _visible_transcript_from_messages



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
    visible_transcript: list[dict] = field(default_factory=list)
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
            "visible_transcript": self.visible_transcript,
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
        self.visible_transcript = _normalize_visible_transcript(data.get("visible_transcript"))
        if not self.visible_transcript and self.messages:
            self.visible_transcript = _visible_transcript_from_messages(self.messages)

