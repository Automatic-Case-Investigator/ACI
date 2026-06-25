from __future__ import annotations

import json
import re




# gpt-oss emits the "harmony" format; vllm's parser sometimes leaks raw control
# tokens (e.g. <|channel|>, <|end|>, <|start|>) into the assistant message. When
# that text is echoed back in history, vllm fails to re-parse it ("unexpected
# tokens remaining in message header"). Strip these before storing any message.
_HARMONY_TOKEN_RE = re.compile(r"<\|[^|>]*\|>")
_LEAKED_TOOL_HEADER_RE = re.compile(r"(?im)^\s*to=functions\.[^\n]*$")
_LEAKED_ROLE_LINE_RE = re.compile(r"(?im)^\s*assistant\s*$")


def _strip_harmony(text):
    if not isinstance(text, str):
        return text
    cleaned = _HARMONY_TOKEN_RE.sub("", text)
    cleaned = _LEAKED_TOOL_HEADER_RE.sub("", cleaned)
    cleaned = _LEAKED_ROLE_LINE_RE.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _sanitize_message(msg):
    """Remove harmony control tokens from an assistant message before it re-enters
    the conversation history."""
    if isinstance(getattr(msg, "content", None), str):
        msg.content = _strip_harmony(msg.content)
    ak = getattr(msg, "additional_kwargs", None)
    if isinstance(ak, dict) and isinstance(ak.get("reasoning_content"), str):
        ak["reasoning_content"] = _strip_harmony(ak["reasoning_content"])
    return msg


def _sanitize_history(messages: list, *, aggressive: bool = False) -> list:
    """Sanitize model history before an LLM call.

    aggressive=True additionally drops assistant chatter that still looks like a
    leaked tool header fragment after cleanup.
    """
    sanitized: list = []
    for msg in messages:
        _sanitize_message(msg)
        content = getattr(msg, "content", None)
        tool_calls = getattr(msg, "tool_calls", None)
        if aggressive and isinstance(content, str) and not tool_calls:
            if "to=functions." in content or "<|start|>" in content or "<|end|>" in content:
                continue
        sanitized.append(msg)

    # Drop orphaned ToolMessages — messages whose tool_call_id has no matching entry
    # in any AIMessage's tool_calls.  These cause a 400 from the OpenAI API on replay.
    known_ids: set[str] = set()
    for msg in sanitized:
        for tc in getattr(msg, "tool_calls", None) or []:
            if isinstance(tc, dict) and tc.get("id"):
                known_ids.add(tc["id"])
    return [
        msg for msg in sanitized
        if not (getattr(msg, "tool_call_id", None) is not None
                and getattr(msg, "tool_call_id") not in known_ids)
    ]


def _normalize(result) -> str:
    """Flatten an MCP tool result to plain text.

    langchain-mcp-adapters returns a list of content blocks, e.g.
    [{"type": "text", "text": "<json>", "id": "lc_..."}]. We extract and
    join the text payloads so callers see the inner JSON/string directly.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        texts: list[str] = []
        for block in result:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif isinstance(block, str):
                texts.append(block)
            else:
                text_attr = getattr(block, "text", None)
                if text_attr is not None:
                    texts.append(text_attr)
        if texts:
            return "\n".join(texts)
    return json.dumps(result, default=str)
