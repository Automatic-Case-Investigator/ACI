"""aci-board MCP server.

Per-session Findings Board for ACI investigation agents.
Run as stdio: python -m aci_board.server
"""
from __future__ import annotations

import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, PromptMessage, TextContent, Tool

from . import store as _store

app = Server("aci-board")
_store.init_db()


def _identity_overrides() -> dict:
    """Board identity is owned by the platform, not the model."""
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
    return [Prompt(name="agent_instructions", description="Findings Board guidance for ACI agents.")]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    if name != "agent_instructions":
        raise ValueError(f"Unknown prompt: {name}")
    return GetPromptResult(
        description="Findings Board guidance for ACI agents.",
        messages=[PromptMessage(
            role="user",
            content=TextContent(type="text", text="""# ACI Findings Board Guidance

The Findings Board contains found artifacts, confirmed facts, and hypotheses for
the current investigation run. It is read by the dashboard and injected into
each task context automatically.

Found artifacts are extracted deterministically from retrieved native events by
the backend. Do not call a tool to add artifacts.

## When to use

- Call `add_fact` when you have confirmed a finding from raw evidence (event IDs,
  timestamps, AVFS paths). Do not add facts from alert text alone.
- Include hypotheses in the required `## Hypotheses` task-output section. The
  backend persists them automatically. You may call `add_hypothesis` for an
  important hypothesis that must be recorded before task completion. A hypothesis
  is a claim ("X happened"), never a question — questions are leads.
- To change a hypothesis's state, restate it in your `## Hypotheses` section using
  the same wording, prefixed with `[Confirmed]` or `[Refuted]`. The board matches it
  to the existing entry and updates the status automatically — this does not create a
  duplicate. Do not invent `[id=...]` tags.

## Confidence levels

- `high`: multiple corroborating raw evidence sources.
- `medium`: single source or circumstantial evidence.
- `low`: inference, pattern match, or assumption without direct evidence.

## Status values

- `observed`: artifact extracted from a retrieved event.
- `open`: not yet verified (default for hypotheses).
- `confirmed`: verified by raw evidence.
- `refuted`: contradicted by raw evidence — keep on the board so the analyst can see it.

## Deduplication

Do not add a fact or hypothesis that is already on the Findings Board. Call `get_board`
first if you are unsure. The pivot node auto-adds facts from your
`## Confirmed Facts` section — you do not need to call `add_fact` for those.
"""),
        )],
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="add_fact",
            description=(
                "Add a confirmed fact to the Findings Board. Only call this when you have raw "
                "evidence (event IDs, timestamps, AVFS paths). Do not add facts from "
                "alert text alone. The platform scopes this to the current run "
                "automatically — do not pass case_id/run_id/agent_name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "One-sentence confirmed fact."},
                    "source": {"type": "string", "description": "Event IDs or AVFS paths supporting this fact."},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "default": "high",
                    },
                },
                "required": ["content"],
            },
        ),
        Tool(
            name="add_hypothesis",
            description=(
                "Add an open hypothesis to the Findings Board. Use for leads not yet confirmed "
                "by raw evidence. The platform scopes this automatically."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "One-sentence hypothesis."},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "default": "medium",
                    },
                },
                "required": ["content"],
            },
        ),
        Tool(
            name="update_entry",
            description="Update the content, confidence, or status of a Findings Board entry.",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "content": {"type": "string"},
                    "source": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "status": {
                        "type": "string",
                        "enum": ["observed", "open", "confirmed", "refuted"],
                    },
                },
                "required": ["id"],
            },
        ),
        Tool(
            name="get_board",
            description=(
                "Return all artifacts, facts, and hypotheses on the current Findings Board. "
                "Findings Board context is injected into each task automatically; call "
                "this only when you need to check entry IDs for update_entry."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="delete_entry",
            description="Remove an entry from the Findings Board.",
            inputSchema={
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    ov = _identity_overrides()
    try:
        if name == "add_fact":
            result = _store.add_entry(
                case_id=_ident(arguments, ov, "case_id"),
                run_id=_ident(arguments, ov, "run_id"),
                agent_name=_ident(arguments, ov, "agent_name"),
                kind="fact",
                content=arguments["content"],
                source=arguments.get("source", ""),
                confidence=arguments.get("confidence", "high"),
                status="confirmed",
            )
        elif name == "add_hypothesis":
            result = _store.add_entry(
                case_id=_ident(arguments, ov, "case_id"),
                run_id=_ident(arguments, ov, "run_id"),
                agent_name=_ident(arguments, ov, "agent_name"),
                kind="hypothesis",
                content=arguments["content"],
                confidence=arguments.get("confidence", "medium"),
                status="open",
            )
        elif name == "update_entry":
            kw = {k: v for k, v in arguments.items() if k != "id"}
            result = _store.update_entry(arguments["id"], **kw)
        elif name == "get_board":
            entries = _store.list_entries(
                _ident(arguments, ov, "case_id"),
                _ident(arguments, ov, "run_id"),
                _ident(arguments, ov, "agent_name"),
            )
            result = {"entries": entries}
        elif name == "delete_entry":
            result = {"deleted": _store.delete_entry(arguments["id"])}
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
