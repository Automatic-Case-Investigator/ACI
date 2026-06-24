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


def _visible_transcript_from_messages(messages: list) -> list[dict]:
    """Recover analyst-visible conversation from legacy persisted messages.

    This is distinct from `messages`, which includes tool-call scaffolding,
    public-intent injections, ToolMessages, and may be compacted. The visible
    transcript is the durable analyst dialogue: user messages and orchestrator
    answers that should always be available on future turns.
    """
    transcript: list[dict] = []
    for msg in messages or []:
        t = getattr(msg, "type", None)
        c = getattr(msg, "content", "") or ""
        if not isinstance(c, str):
            c = str(c)
        c = c.strip()
        if not c:
            continue
        if t == "human":
            if c.startswith("[Public intent already shown to the analyst]"):
                continue
            transcript.append({"role": "user", "content": c})
        elif t == "ai":
            tool_calls = getattr(msg, "tool_calls", None) or []
            if tool_calls and not c:
                continue
            transcript.append({"role": "assistant", "content": c})
    return transcript


def _normalize_visible_transcript(data) -> list[dict]:
    items: list[dict] = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role not in {"user", "assistant"} or not isinstance(content, str):
            continue
        if content.strip():
            items.append({"role": role, "content": content})
    return items


def _append_visible(transcript: list[dict], role: str, content: str) -> None:
    content = (content or "").strip()
    if role not in {"user", "assistant"} or not content:
        return
    item = {"role": role, "content": content}
    if transcript and transcript[-1] == item:
        return
    transcript.append(item)


async def _summarize_conversation(text: str) -> str:
    """Compact a long conversation transcript with one model call (overflow only).

    Reuses the summarization instruction wording from `graph._compact_history`.
    Returns the original text on any failure so the caller can continue.
    """
    try:
        model = await build_model()
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

