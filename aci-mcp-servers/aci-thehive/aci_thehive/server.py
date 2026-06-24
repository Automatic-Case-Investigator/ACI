"""aci-thehive MCP server.

Run as stdio: python -m aci_thehive.server
"""
from __future__ import annotations

import json
import os
import traceback

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, PromptMessage, TextContent, Tool

from .client import TheHiveClient

app = Server("aci-thehive")
_client: TheHiveClient | None = None


def _get_client() -> TheHiveClient:
    """Build the TheHive client from the env vars the parent populated.

    The runtime resolves connection settings (DB-over-defaults) and passes them
    to this subprocess as THEHIVE_* env vars (see agent/runtime/providers/thehive.py).
    We must NOT re-query the DB here: call_tool runs on the asyncio event loop, and
    synchronous Django ORM there raises SynchronousOnlyOperation — which previously
    fell back silently to empty defaults. Reading os.environ mirrors the Wazuh server.
    """
    global _client
    if _client is None:
        _client = TheHiveClient(
            host=os.environ.get("THEHIVE_HOST", ""),
            port=os.environ.get("THEHIVE_PORT", "9000"),
            api_key=os.environ.get("THEHIVE_API_KEY", ""),
            verify_tls=os.environ.get("THEHIVE_VERIFY_TLS", "true"),
        )
    return _client


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="agent_instructions",
            description="TheHive case and alert workflow guidance for ACI agents.",
        )
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    if name != "agent_instructions":
        raise ValueError(f"Unknown prompt: {name}")
    return GetPromptResult(
        description="TheHive case and alert workflow guidance for ACI agents.",
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text="""# TheHive Guidance

This server is the source for case records, linked alert summaries, and analyst-facing
case updates.

## Case IDs

TheHive case IDs always begin with a tilde (`~`), e.g. `~245862456`. **Always
preserve the `~` prefix** when passing a case ID to any tool. A numeric ID without
the tilde (e.g. `245862456`) is not a valid case ID and will return 404. If the
analyst provides a case ID without the tilde, add it before calling any tool.

## Case workflow

- For case-specific work, start by reading the case record. Capture title,
  description, severity, status, tags, created/updated timestamps, and any analyst
  context already present.
- Read linked alerts before deciding what happened. The case record alone is usually
  insufficient for triage.
- For broad triage, summarize the case and alerts into distinct threads before
  creating deeper investigation work.
- For narrow follow-up questions, reuse known case context when available, then read
  only the additional case/alert detail needed to answer the question.

## Alert handling

- Linked alerts are summarized to avoid context overload. Use pagination/limits
  deliberately, and fetch full alert details only for alerts that matter to the
  current task.
- Treat alert fields as pivots, not final proof. Important pivots commonly include
  source, sourceRef, title, type, severity, tags, affected assets, users, IPs, and
  timestamps.
- Use alert timestamps to derive absolute time windows for SIEM investigation. Do not
  assume the incident is recent.
- sourceRef may be a useful correlation hint, but do not assume it is a raw SIEM
  document id unless the alert/source explicitly establishes that.

## Reporting back to TheHive

- Post the final case report only after the investigation is complete using
  `post_case_report`. This creates a new page under the case's Pages tab (not a
  history comment). The report should include executive summary, timeline, confirmed
  findings with evidence references, suspicious observations, open questions, and
  recommended next actions. Optionally set `title` to something descriptive (e.g.
  "Triage Report", "Investigation Report", "Malware Analysis").

## Accuracy rules

- Do not invent case facts, alert details, severities, timestamps, users, hosts, IPs,
  or statuses.
- Distinguish between facts returned by TheHive, raw evidence from SIEM, and your
  analysis.
- If TheHive access fails or returns incomplete data, say exactly what could not be
  retrieved and continue only with clearly stated uncertainty.
""",
                ),
            )
        ],
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_case",
            description="Retrieve a TheHive case by ID. Returns title, description, severity, status, tags, and timestamps.",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "TheHive case ID (e.g. '~12345')."},
                },
                "required": ["case_id"],
            },
        ),
        Tool(
            name="list_cases",
            description="List recent TheHive cases.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum cases to return (default 20).",
                        "default": 20,
                    },
                },
            },
        ),
        Tool(
            name="list_case_alerts",
            description=(
                "Summarise the alerts linked to a TheHive case. Returns a deduplicated, "
                "grouped view: `groups` (each rule/title with a count and first/last-seen "
                "window so a brute-force flood of identical alerts collapses to one row), "
                "`distinct_alert_types`, `time_range`, and a small `alerts` sample. "
                "Reason from `groups` and `time_range`; use get_alert for full detail on a "
                "specific alert. `max_results` only bounds the inline sample (capped at 20); "
                "grouping always covers the whole case."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "TheHive case ID."},
                    "max_results": {
                        "type": "integer",
                        "description": "Max alerts in the inline sample (default 20, hard cap 20). Grouping covers all alerts regardless.",
                        "default": 20,
                    },
                },
                "required": ["case_id"],
            },
        ),
        Tool(
            name="get_alert",
            description="Retrieve a specific TheHive alert by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "TheHive alert ID."},
                },
                "required": ["alert_id"],
            },
        ),
        Tool(
            name="post_case_report",
            description=(
                "Create a new page in the TheHive case containing the investigation report. "
                "Call this once at the end of the investigation with the complete grounded report. "
                "The page appears under the case's Pages tab, not as a history record."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "TheHive case ID."},
                    "summary": {
                        "type": "string",
                        "description": "Markdown report: executive summary, timeline, confirmed findings with evidence references, open questions, and recommended actions.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Page title (default: 'Investigation Report').",
                        "default": "Investigation Report",
                    },
                },
                "required": ["case_id", "summary"],
            },
        ),
        Tool(
            name="update_case",
            description="Update fields on a TheHive case (e.g. status, severity, assignee, tags).",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "TheHive case ID."},
                    "fields": {
                        "type": "object",
                        "description": "Fields to update, e.g. {\"status\": \"Resolved\"} or {\"severity\": 3}.",
                    },
                },
                "required": ["case_id", "fields"],
            },
        ),
        Tool(
            name="post_case_comment",
            description="Post an ACI workflow note to a TheHive case as a case page.",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "TheHive case ID."},
                    "message": {"type": "string", "description": "Comment text (markdown supported)."},
                },
                "required": ["case_id", "message"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = _get_client()
    try:
        if name == "get_case":
            result = client.get_case(arguments["case_id"])
        elif name == "list_cases":
            result = client.list_cases(max_results=int(arguments.get("max_results", 20)))
        elif name == "list_case_alerts":
            result = client.list_case_alerts(
                arguments["case_id"],
                max_results=int(arguments.get("max_results", 20)),
            )
        elif name == "get_alert":
            result = client.get_alert(arguments["alert_id"])
        elif name == "post_case_report":
            result = client.post_report(
                arguments["case_id"],
                arguments["summary"],
                title=arguments.get("title", "Investigation Report"),
            )
        elif name == "update_case":
            result = client.update_case(arguments["case_id"], arguments["fields"])
        elif name == "post_case_comment":
            result = client.post_case_comment(arguments["case_id"], arguments["message"])
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        result = {"error": traceback.format_exc()}

    return [TextContent(type="text", text=json.dumps(result, default=str))]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
