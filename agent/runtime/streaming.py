from __future__ import annotations

from .logbus import emit, summarize_stream


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(block, str):
                parts.append(block)
        return "".join(parts)
    return ""


async def invoke_streaming(
    bound,
    messages: list,
    agent_name: str,
    source: str,
    *,
    event_kind: str = "stream",
    event_metadata: dict | None = None,
):
    """Stream text chunks to the live dashboard while preserving final AIMessage.

    LangChain's `astream` yields AIMessageChunk objects. Adding chunks together
    preserves tool-call metadata, so callers can keep their existing
    tool-call/assessment logic after streaming completes.
    """
    if not hasattr(bound, "astream"):
        return await bound.ainvoke(messages)

    accumulated = None
    saw_chunk = False
    async for chunk in bound.astream(messages):
        saw_chunk = True
        accumulated = chunk if accumulated is None else accumulated + chunk
        text = _chunk_text(chunk)
        if text:
            emit(
                source,
                event_kind,
                summarize_stream(text),
                detail=text,
                metadata=event_metadata,
            )

    if not saw_chunk:
        return await bound.ainvoke(messages)
    return accumulated
