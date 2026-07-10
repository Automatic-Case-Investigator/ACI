from __future__ import annotations

import json
import posixpath
from typing import Awaitable, Callable

from .indexer import MEMORY_FILE, parent_index_dirs, upsert_memory_content


ToolCall = Callable[[str, dict], Awaitable[str]]


def avfs_home() -> str:
    from agent.runtime.infra.avfs import home_dir

    return home_dir()


def index_stop_for(path: str) -> str:
    home = avfs_home()
    parts = path.strip("/").split("/")
    if len(parts) >= 4 and parts[2] in {"cases", "triage", "investigation", "memory"}:
        if parts[2] == "cases" and len(parts) >= 4:
            return f"{home}/cases/{parts[3]}"
        if parts[2] in {"triage", "investigation"} and len(parts) >= 4:
            return f"{home}/{parts[2]}/{parts[3]}"
        if parts[2] == "memory":
            return f"{home}/memory"
    if len(parts) >= 5 and parts[2] == "helpers":
        return f"{home}/helpers/{parts[3]}/{parts[4]}"
    return home


async def write_file(
    *,
    call_tool: ToolCall,
    path: str,
    content: str,
    created_by: str,
    summary: str | None = None,
    durable: bool = True,
) -> str:
    await ensure_parent(call_tool, path)
    result = await call_tool("write", {"path": path, "content": content})
    if durable and not _is_error(result):
        await update_memory_indexes(
            call_tool=call_tool,
            changed_path=path,
            created_by=created_by,
            summary=summary,
        )
    return result


async def ensure_parent(call_tool: ToolCall, path: str) -> None:
    parent = posixpath.dirname(path)
    if parent:
        await call_tool("mkdir", {"path": parent, "parents": True})


async def update_memory_indexes(
    *,
    call_tool: ToolCall,
    changed_path: str,
    created_by: str,
    summary: str | None = None,
) -> None:
    if posixpath.basename(changed_path) == MEMORY_FILE:
        return
    stop_at = index_stop_for(changed_path)
    for directory in parent_index_dirs(changed_path, stop_at=stop_at):
        memory_path = f"{directory}/{MEMORY_FILE}"
        existing = await _read_text(call_tool, memory_path)
        body = upsert_memory_content(
            existing,
            directory=directory,
            changed_path=changed_path,
            created_by=created_by,
            summary=summary,
        )
        await ensure_parent(call_tool, memory_path)
        await call_tool("write", {"path": memory_path, "content": body})


async def _read_text(call_tool: ToolCall, path: str) -> str:
    raw = await call_tool("read", {"path": path})
    if _is_error(raw):
        return ""
    try:
        data = json.loads(raw)
    except Exception:
        return raw if isinstance(raw, str) else ""
    if isinstance(data, dict):
        value = data.get("content") or data.get("text") or data.get("data")
        return value if isinstance(value, str) else ""
    return raw if isinstance(raw, str) else ""


def _is_error(raw: str) -> bool:
    if not raw:
        return False
    if isinstance(raw, str) and raw.startswith("Error:"):
        return True
    try:
        data = json.loads(raw)
    except Exception:
        return False
    return isinstance(data, dict) and (data.get("ok") is False or bool(data.get("error")))
