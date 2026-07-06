from __future__ import annotations

import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ..engine.streaming import invoke_streaming
from ..infra.avfs import home_dir
from ..infra.logbus import emit, src_label, summarize_args, summarize_result

from .sanitize import _normalize, _sanitize_history, _sanitize_message
from .state import AgentState

log = logging.getLogger(__name__)



def _tmap(tools: list) -> dict:
    return {t.name: t for t in tools}


_SEED_TASK_TITLE = "populate investigation queue"

# claim_next and complete_task are graph-managed: the `claim` node owns claiming
# and the `assess` node owns completion (always with a non-empty summary). Exposing
# them to the model lets it mark a task `claimed` before it runs (queue looks empty)
# or `complete` a task mid-investigation before any real work is done. The graph
# completes every claimed task itself, so the model never needs either.
_GRAPH_MANAGED_TOOLS = frozenset({"claim_next", "complete_task"})

# Write tools that modify the case management system. The investigation agent
# must never call these autonomously — writes require explicit analyst authorization
# which only the orchestrator can grant. Keeping them out of the model tool list
# is the only reliable enforcement (prompt instructions are overridden by MCP guidance).
_CASE_WRITE_TOOLS = frozenset({
    "post_case_report",
    "update_case",
    "close_case",
    "resolve_case",
    "add_case_comment",
    "post_case_comment",
})

_MAX_SYNTHESIS_FINDINGS_CHARS = 2000


def _model_tools_for_agent(
    agent_name: str, tools: list, current_task: dict | None = None
) -> list:
    excluded = set(_GRAPH_MANAGED_TOOLS)
    if agent_name == "triage":
        excluded.add("create_task")
    if agent_name == "investigation":
        # Tasks are created by the seeder (at seed time) and pivot node (for new leads).
        # The investigation model never calls create_task directly.
        excluded.add("create_task")
        # Investigation agents must not write to the case system without explicit
        # analyst authorization (which the orchestrator enforces). Hide write tools
        # so MCP instructions cannot prompt the model into calling them autonomously.
        excluded |= _CASE_WRITE_TOOLS
    return [t for t in tools if getattr(t, "name", "") not in excluded]


async def _invoke_bound_model(bound, messages: list, agent_name: str):
    """Invoke the chat model; on known vLLM header parsing failure, retry once
    with aggressive history sanitation."""
    source = src_label(agent_name)
    try:
        return await invoke_streaming(bound, messages, agent_name, source)
    except Exception as exc:
        if "unexpected tokens remaining in message header" not in str(exc):
            raise
        repaired = _sanitize_history(messages, aggressive=True)
        log.warning(
            "[%s] think -- retrying after sanitizing leaked control-header text",
            agent_name,
        )
        emit(
            src_label(agent_name),
            "warning",
            "retrying model call after sanitizing leaked control-header text",
            detail=str(exc),
        )
        try:
            return await invoke_streaming(bound, repaired, agent_name, source)
        except Exception as exc2:
            if "unexpected tokens remaining in message header" not in str(exc2):
                raise
            from langchain_core.messages import AIMessage
            log.warning(
                "[%s] think -- double harmony-token failure, returning empty response",
                agent_name,
            )
            emit(src_label(agent_name), "warning", "double harmony-token failure — empty response used")
            return AIMessage(content="")


def _first_int(d: dict, keys) -> int:
    """First truthy value among `keys` in `d`, else 0."""
    for key in keys:
        value = d.get(key)
        if value:
            return value
    return 0


def _extract_input_tokens(response) -> int:
    """Pull input token count from a LangChain AIMessage (OpenAI-compatible)."""
    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        return _first_int(usage, ("input_tokens", "prompt_tokens", "input_token_count"))
    meta = getattr(response, "response_metadata", None)
    if isinstance(meta, dict):
        tu = meta.get("token_usage") or meta.get("usage") or {}
        return _first_int(tu, ("prompt_tokens", "input_tokens", "input_token_count"))
    return 0


def _should_compact(ctx_tokens: int) -> bool:
    if not ctx_tokens:
        return False
    try:
        from ..engine.model_client import model_context_length_sync
        limit = model_context_length_sync()
    except Exception:
        limit = 131072
    return ctx_tokens >= int(limit * 0.8)


def _is_tool_related(msg) -> bool:
    """True for raw tool evidence: a ToolMessage or the assistant turn that
    called the tool. These must never be summarised away — they carry the
    grounded findings (e.g. a reverse shell in a SIEM result) the final report
    is built from."""
    return isinstance(msg, ToolMessage) or bool(getattr(msg, "tool_calls", None))


async def _compact_history(messages: list, bound, agent_name: str) -> list:
    """Summarise old conversation turns to reduce context size.

    Never compacts the current task's tool results: every ToolMessage and the
    assistant message that issued the call are kept verbatim. Only standalone
    text (the task brief, model narration) from before the recent window is
    replaced by a single summary HumanMessage. Returns the original list on any
    failure so the caller can continue normally.
    """
    sys_msgs = [m for m in messages if isinstance(m, SystemMessage)]
    conv_msgs = [m for m in messages if not isinstance(m, SystemMessage)]
    if len(conv_msgs) < 6:
        return messages

    keep = 4
    head = conv_msgs[:-keep]
    recent = conv_msgs[-keep:]

    # Split the head into tool evidence (preserved in place) and free text
    # (summarisable). Keeping the assistant tool-call turns alongside their
    # ToolMessages also preserves tool_call_id pairing for API replay.
    preserved_head = [m for m in head if _is_tool_related(m)]
    summarizable = [m for m in head if not _is_tool_related(m)]
    if not summarizable:
        return messages  # nothing safe to compact without dropping evidence

    try:
        resp = await bound.ainvoke([
            *sys_msgs,
            *summarizable,
            HumanMessage(content=(
                "Concisely summarise the above conversation. Preserve: case IDs, "
                "host names, IPs, key findings, tool results still relevant, and "
                "any context established so far. This replaces the prior history."
            )),
        ])
        _sanitize_message(resp)
        summary = (resp.content or "").strip()
    except Exception:
        return messages

    if not summary:
        return messages

    return [
        *sys_msgs,
        HumanMessage(content=f"[Prior context summary]\n\n{summary}"),
        *preserved_head,
        *recent,
    ]


async def _call(tool, args: dict, *, _dbg: str | None = None) -> str:
    name = getattr(tool, "name", "?")
    if _dbg is not None:
        from ..infra.logbus import debug_mode_enabled
        if debug_mode_enabled():
            emit(_dbg, "call", f"[graph] {name}({summarize_args(args)})",
                 detail=json.dumps(args, indent=2, default=str))
    try:
        result = await tool.ainvoke(args)
        result = _normalize(result)
    except Exception as exc:
        result = f"Error: {exc}"
    if _dbg is not None:
        from ..infra.logbus import debug_mode_enabled
        if debug_mode_enabled():
            emit(_dbg, "result", f"[graph] {name}: {summarize_result(name, result)}", detail=result)
    return result


def _emit_node_entry(src: str, node: str, state: AgentState) -> None:
    """Emit a [route] event at node entry when debug mode is on."""
    from ..infra.logbus import debug_mode_enabled
    if not debug_mode_enabled():
        return
    task_title = (state.get("current_task") or {}).get("title") or ""
    meta: dict = {
        "node": node,
        "steps": state.get("steps", 0),
        "max_steps": state.get("max_steps"),
        "tool_calls_made": state.get("tool_calls_made", 0),
        "max_tool_calls": state.get("max_tool_calls"),
        "status": state.get("status") or "",
    }
    if task_title:
        meta["current_task"] = task_title
    summary = (
        f"→ {node}  steps={meta['steps']}/{meta['max_steps']}  "
        f"calls={meta['tool_calls_made']}/{meta['max_tool_calls']}"
    )
    if task_title:
        summary += f"  task={task_title[:50]!r}"
    if meta["status"]:
        summary += f"  status={meta['status']}"
    emit(src, "route", summary, detail=json.dumps(meta, indent=2))


async def _list_tasks(tools: list, case_id: str, run_id: str, agent_name: str) -> list:
    """Return all tasks for the current run (empty list on failure)."""
    list_fn = _tmap(tools).get("list_tasks")
    if list_fn is None:
        return []
    raw = await _call(list_fn, {"case_id": case_id, "run_id": run_id, "agent_name": agent_name})
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        tasks = data if isinstance(data, list) else data.get("tasks", [])
        return tasks if isinstance(tasks, list) else []
    except Exception:
        return []


async def _has_pending_tasks(tools: list, case_id: str, run_id: str, agent_name: str) -> bool:
    tasks = await _list_tasks(tools, case_id, run_id, agent_name)
    return any(t.get("status") == "pending" for t in tasks)


def _parse_claimed_task(raw):
    """Unwrap claim_next's `{"task": {...}}` response into a task dict or None."""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return None
    if isinstance(data, dict) and "task" in data:
        data = data["task"]
    return data if isinstance(data, dict) and "id" in data else None


async def _reclaim_stale_tasks(tools: list, state: AgentState, *, _dbg: str | None = None) -> int:
    """Reset this run's tasks stuck in `claimed` back to `pending`, returning the count.

    `claim` runs only between tasks, so for a single-threaded run no task should be
    legitimately `claimed` at this point. A leftover `claimed` row means a prior cycle
    was cut short (budget exhaustion, crash, interrupted reload) without completing —
    and since `claim_next` selects only `pending` rows, that task is invisible and the
    queue looks empty while work remains. Recovering it lets the loop resume instead of
    finishing prematurely.
    """
    update_fn = _tmap(tools).get("update_task")
    if update_fn is None:
        return 0
    tasks = await _list_tasks(tools, state["case_id"], state["run_id"], state["agent_name"])
    stale = [t for t in tasks if t.get("status") == "claimed" and t.get("id")]
    for t in stale:
        await _call(update_fn, {"task_id": t["id"], "status": "pending"}, _dbg=_dbg)
    return len(stale)



# Hard cap on any single tool result fed back into the conversation. Prevents a
# pathological tool (e.g. a case linking thousands of alerts) from overflowing
# the model's context window. ~24k chars =~ 6k tokens.
_MAX_TOOL_RESULT_CHARS = 24000


def _cap_tool_result(content: str) -> str:
    if len(content) <= _MAX_TOOL_RESULT_CHARS:
        return content
    head = content[:_MAX_TOOL_RESULT_CHARS]
    return (
        f"{head}\n\n...[truncated {len(content) - _MAX_TOOL_RESULT_CHARS} chars -- "
        "result too large; narrow your query or request fewer items]"
    )


def _is_error_tool_result(content: str) -> bool:
    c = (content or "").strip()
    if c.startswith("Error:"):
        return True
    try:
        obj = json.loads(c)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    # AVFS-style envelope {"ok": bool, "data": ..., "error": null|msg}: a present
    # `error` key is NOT itself a failure — `error: null` with `ok: true` is success.
    # Only flag when the envelope says failure, or when a bare `error` is truthy.
    if "ok" in obj:
        return obj.get("ok") is False or bool(obj.get("error"))
    return bool(obj.get("error"))


def _expand_tilde_args(args: dict) -> dict:
    """Expand leading ~ in any string argument that looks like an AVFS path.

    The model is instructed to use ~/cases/... notation, but AVFS requires
    absolute paths. This runs before every tool call so the model's shorthand
    always resolves correctly regardless of which AVFS tool is invoked.
    """
    home = home_dir()
    expanded = {}
    for k, v in args.items():
        if isinstance(v, str) and (v == "~" or v.startswith("~/")):
            expanded[k] = home + v[1:]
        else:
            expanded[k] = v
    return expanded




async def _ensure_parent_dir(tmap: dict, path) -> None:
    """Create the parent directory of an AVFS path (mkdir -p). No-op if already present."""
    mkdir = tmap.get("mkdir")
    if not mkdir or not isinstance(path, str) or "/" not in path:
        return
    parent = path.rsplit("/", 1)[0]
    if parent:
        await _call(mkdir, {"path": parent, "parents": True})


async def _ensure_workspace_dirs(tools: list, *, _dbg: str | None = None) -> int:
    """Pre-create the standard AVFS home folders the AVFS server prompt advertises.

    The AVFS prompt tells the agent to read `~/sessions`, `~/tasks`, `~/memory`,
    `~/knowledge` (and to read `/sessions` first to resume). On a fresh run those
    dirs don't exist, so the agent's prompt-directed `ls` returns ENOENT — a failing
    round-trip repeated per task. Creating them up front makes those reads return an
    empty listing instead. No-op when AVFS (mkdir) is not configured. Returns the
    number of dirs requested (0 when AVFS is absent)."""
    from ..infra.avfs import workspace_dirs

    mkdir = _tmap(tools).get("mkdir")
    if mkdir is None:
        return 0
    dirs = workspace_dirs()
    for d in dirs:
        await _call(mkdir, {"path": d, "parents": True}, _dbg=_dbg)
    return len(dirs)


async def _cancel_requested(run_id: str) -> bool:
    try:
        from ...models import AgentRun

        run = await AgentRun.objects.aget(id=run_id)
        return run.status == AgentRun.STATUS_CANCELLED or bool((run.metadata or {}).get("cancel_requested"))
    except Exception:
        return False
