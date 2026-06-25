"""aci-wazuh MCP server.

Run as stdio: python -m aci_wazuh.server
"""
from __future__ import annotations

import json
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, PromptMessage, TextContent, Tool

from .client import WazuhClient
from .prompts import AGENT_INSTRUCTIONS
from .tool_schemas import wazuh_tools

app = Server("aci-wazuh")
_client: WazuhClient | None = None


def _get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="agent_instructions",
            description="Wazuh SIEM query workflow guidance for ACI agents.",
        )
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    if name != "agent_instructions":
        raise ValueError(f"Unknown prompt: {name}")
    return GetPromptResult(
        description="Wazuh SIEM query workflow guidance for ACI agents.",
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text=AGENT_INSTRUCTIONS,
                ),
            )
        ],
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    return wazuh_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = _get_client()
    try:
        if name == "search":
            result = client.search(
                query=arguments["query"],
                index_pattern=arguments.get("index_pattern"),
            )
        elif name == "get_event":
            result = client.get_event(
                event_id=arguments["event_id"],
                index_pattern=arguments.get("index_pattern"),
            )
        elif name == "profile_field":
            result = client.profile_field(
                field=arguments["field"],
                index_pattern=arguments.get("index_pattern"),
                time_range=arguments.get("time_range"),
                top_n=int(arguments.get("top_n", 10)),
                query=arguments.get("query"),
            )
        elif name == "search_keyword":
            result = client.search_keyword(
                query=arguments["query"],
                index_pattern=arguments.get("index_pattern"),
                time_range=arguments.get("time_range"),
                max_results=int(arguments.get("max_results", 20)),
            )
        elif name == "list_indices":
            result = {"indices": client.list_indices()}
        elif name == "get_index_schema":
            result = client.get_index_schema(arguments["index_pattern"])
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
