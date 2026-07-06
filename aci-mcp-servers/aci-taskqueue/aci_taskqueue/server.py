"""aci-taskqueue MCP server.

Run as stdio: python -m aci_taskqueue.server
"""
from __future__ import annotations

import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, PromptMessage, TextContent, Tool

from . import store as _store

app = Server("aci-taskqueue")
_store.init_db()

def _identity_overrides() -> dict:
    """Queue identity (case/run/agent) is owned by the platform, not the model.

    When the runtime spawns this server for a specific agent run it injects these
    via env. We then OVERRIDE any model-supplied case_id/run_id/agent_name so a task
    can never be filed under the wrong queue (e.g. the model copying the AVFS agent
    id into agent_name). Absent env (ad-hoc use), model-supplied values are kept.
    """
    out: dict = {}
    for key, env in (("case_id", "ACI_CASE_ID"), ("run_id", "ACI_RUN_ID"),
                     ("agent_name", "ACI_AGENT_NAME")):
        val = os.environ.get(env)
        if val:
            out[key] = val
    return out


def _ident(arguments: dict, overrides: dict, key: str) -> str:
    val = overrides.get(key) or arguments.get(key)
    if not val:
        raise ValueError(f"{key} is required but was not supplied by the platform or caller.")
    return val


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="agent_instructions",
            description="Task queue workflow guidance for ACI agents.",
        )
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    if name != "agent_instructions":
        raise ValueError(f"Unknown prompt: {name}")
    return GetPromptResult(
        description="Task queue workflow guidance for ACI agents.",
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text="""# ACI Task Queue Guidance

This server owns per-agent work queues. Queue rows are execution units, not notes.

## Execution model

- **Do not call `claim_next` or `complete_task`.** The platform claims and completes
  tasks for you via the graph runtime. Calling these yourself will mark tasks as
  claimed before they run and cause the queue to appear empty — skipping all work.
- The platform starts each work cycle by claiming the next pending task and ends it
  by completing the task once you finish. Your job is the investigation in between.
- Work one claimed task to a clear outcome before moving on.
- The queue is ordered by priority descending, then creation time ascending.
- A task can be edited by a human while you run. Re-read queue/task state when exact
  ordering or status matters.

## Creating follow-up work

Create a follow-up task when you discover a lead that needs separate investigation:

- One task should cover one concrete investigative action or question.
- Title should be short, specific, and outcome-oriented.
- Description should include pivots, assets, users, timestamps/time windows, expected
  evidence to retrieve, and where the resulting evidence/finding should be recorded.
- Do NOT pass case_id, run_id, or agent_name — the platform fills these for you.
  In particular, never use your AVFS home/agent id (e.g. `agent_1`) as agent_name;
  the queue scopes itself to the current run automatically.
- Triage agents should not populate the investigation queue. They should return a
  triage report with a proposed investigation plan to the orchestrator. After analyst
  confirmation, the investigation agent converts that handoff into its own queue tasks.
- Set origin to agent for tasks you create yourself.

## Priority guidance

Use priority 0-100. Higher runs earlier.

- 95-100: active compromise, exfiltration, live attacker, critical asset risk.
- 85-94: confirmed lateral movement, successful authentication after attack, malware
  execution, persistence, privileged access.
- 70-84: strong suspicious activity requiring evidence collection.
- 50-69: enrichment, correlation, scoping, lower-risk pivots.
- 30-49: reporting, cleanup, non-urgent context.
- Below 30: optional or nice-to-have follow-up.

## Completing and updating tasks

- Complete a task only when you have a meaningful result. Summary should be one or two
  evidence-backed sentences and should include important workspace evidence paths when
  available.
- If no evidence was found, summarize what was checked and why that is sufficient or
  what uncertainty remains.
- Dismiss a task when it is irrelevant or superseded. Include the reason.
- Mark a task blocked when external input, missing data, credentials, or unavailable
  infrastructure prevents progress. State exactly what is needed.
- Use failure only for an execution/tool error that prevented the task from being
  assessed.

## Queue hygiene

- Prefer fewer, focused tasks over many vague tasks.
- Do not create duplicate work if prior queue items or workspace records already cover
  the lead.
- When creating several tasks, prioritize high-risk or time-sensitive leads first.
""",
                ),
            )
        ],
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="create_task",
            description=(
                "Add a task to YOUR OWN queue. The platform automatically files it under "
                "the current case, run, and agent — do NOT set case_id/run_id/agent_name "
                "(they are auto-managed and any value you pass is ignored). Only provide "
                "title, description, and priority."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string", "default": ""},
                    "priority": {"type": "integer", "default": 50, "description": "0–100; higher = earlier."},
                    "origin": {"type": "string", "default": "agent", "enum": ["agent", "human"]},
                },
                "required": ["title"],
            },
        ),
        Tool(
            name="list_tasks",
            description=(
                "List tasks in YOUR OWN queue, ordered by priority. The platform scopes "
                "this to the current case/run/agent automatically; no arguments needed."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="claim_next",
            description=(
                "Atomically claim the highest-priority pending task from YOUR OWN queue. "
                "Scoped to the current case/run/agent automatically; no arguments needed. "
                "The platform normally claims for you — only call this if explicitly asked."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="complete_task",
            description="Mark a task complete with a brief summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "summary": {"type": "string"},
                    "avfs_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "AVFS paths to evidence produced by this task.",
                    },
                },
                "required": ["task_id", "summary"],
            },
        ),
        Tool(
            name="fail_task",
            description="Mark a task failed with a reason.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["task_id", "reason"],
            },
        ),
        Tool(
            name="dismiss_task",
            description="Dismiss a task (remove from execution without deleting).",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "reason": {"type": "string", "default": ""},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="delete_task",
            description="Hard-delete a task from the queue.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="update_task",
            description=(
                "Edit a task's title, description, priority, or lifecycle status. "
                "`claimed` and `completed` are owned by the platform runtime and cannot "
                "be set here — raise priority to run a pending task sooner, or use "
                "dismiss/fail/blocked to take a task out of the queue."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "priority": {"type": "integer", "description": "0–100; higher = claimed earlier."},
                    "status": {"type": "string", "enum": ["pending", "failed", "dismissed", "blocked"]},
                },
                "required": ["task_id"],
            },
        ),
        Tool(
            name="reopen_task",
            description="Move a completed, failed, or dismissed task back to pending.",
            inputSchema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    ov = _identity_overrides()
    try:
        if name == "create_task":
            result = _store.agent_visible_task(_store.create_task(
                case_id=_ident(arguments, ov, "case_id"),
                run_id=_ident(arguments, ov, "run_id"),
                agent_name=_ident(arguments, ov, "agent_name"),
                title=arguments["title"],
                description=arguments.get("description", ""),
                priority=int(arguments.get("priority", 50)),
                origin=arguments.get("origin", "agent"),
            ))
        elif name == "list_tasks":
            tasks = _store.list_tasks(
                _ident(arguments, ov, "case_id"),
                _ident(arguments, ov, "run_id"),
                _ident(arguments, ov, "agent_name"),
            )
            result = {"tasks": _store.agent_visible_tasks(tasks)}
        elif name == "claim_next":
            task = _store.claim_next(
                _ident(arguments, ov, "case_id"),
                _ident(arguments, ov, "run_id"),
                _ident(arguments, ov, "agent_name"),
            )
            result = {"task": _store.agent_visible_task(task)}
        elif name == "complete_task":
            result = _store.agent_visible_task(_store.complete_task(
                arguments["task_id"],
                arguments["summary"],
                arguments.get("avfs_paths"),
            ))
        elif name == "fail_task":
            result = _store.agent_visible_task(_store.fail_task(arguments["task_id"], arguments["reason"]))
        elif name == "dismiss_task":
            result = _store.agent_visible_task(_store.dismiss_task(arguments["task_id"], arguments.get("reason", "")))
        elif name == "delete_task":
            result = {"deleted": _store.delete_task(arguments["task_id"])}
        elif name == "update_task":
            kw = {k: v for k, v in arguments.items() if k != "task_id"}
            # claimed/completed are graph-managed; never let a caller set them here.
            if kw.get("status") in {"claimed", "completed"}:
                result = {"error": "status 'claimed'/'completed' is managed by the platform; not settable via update_task"}
            else:
                result = _store.agent_visible_task(_store.update_task(arguments["task_id"], **kw))
        elif name == "reopen_task":
            result = _store.agent_visible_task(_store.reopen_task(arguments["task_id"]))
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        result = {"error": str(exc)}

    return [TextContent(type="text", text=json.dumps(result, default=str))]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
