"""Public reasoning-summary generation for agent action turns.

The summary reports established state, its significance, and the next action. It
is not hidden chain-of-thought. It is generated without bound actions and fully
streamed before the action model may request an external capability.
"""
from __future__ import annotations

from dataclasses import dataclass

from langchain_core.messages import HumanMessage

from ..infra.logbus import emit, summarize_intent
from ..engine.streaming import invoke_streaming


@dataclass(frozen=True)
class IntentResult:
    text: str
    sequence: int
    streamed: bool = False


async def generate_public_intent(
    model,
    messages: list,
    *,
    source: str,
    sequence: int,
    task_title: str = "",
    available_tools: list[str] | None = None,
) -> IntentResult:
    """Generate and stream one state-grounded public reasoning summary."""
    tools = ", ".join(available_tools or []) or "(none)"
    prompt = HumanMessage(content=(
        "Before taking the next action, think out loud for the observer in a concise, "
        "natural progress narrative. Explain what relevant state or results are already "
        "established, how you currently interpret them, what remains uncertain or "
        "blocked, and what you intend to do next and why. Use only information supported "
        "by the available context.\n\n"
        "Output only a few sentences only.\n\n"
        f"Current objective: {task_title or '(use the active context)'}\n"
        f"Available external capabilities: {tools}"
    ))
    metadata = {"intent_sequence": sequence}
    try:
        response = await invoke_streaming(
            model,
            list(messages) + [prompt],
            "intent",
            source,
            event_kind="intent_delta",
            event_metadata=metadata,
        )
        text = (getattr(response, "content", "") or "").strip()
    except Exception:
        text = ""

    if text:
        emit(
            source,
            "intent",
            summarize_intent(text),
            detail=text,
            metadata=metadata,
        )
    return IntentResult(text, sequence, streamed=bool(text))
