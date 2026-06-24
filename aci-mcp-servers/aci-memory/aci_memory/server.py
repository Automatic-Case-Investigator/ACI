"""aci-memory MCP server.

Read-only access to curated SOC memory: reviewed FP/TP patterns, computed
baselines, and analyst feedback. Writes happen through the Django admin only.

Run as stdio: python -m aci_memory.server
"""
from __future__ import annotations

import json
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, PromptMessage, TextContent, Tool

from . import store as _store

app = Server("aci-memory")


@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="agent_instructions",
            description="How to use curated SOC memory during triage and investigation.",
        )
    ]


@app.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
    if name != "agent_instructions":
        raise ValueError(f"Unknown prompt: {name}")
    return GetPromptResult(
        description="SOC memory usage guidance for ACI agents.",
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(
                    type="text",
                    text="""# ACI Memory Guidance

This server exposes curated, human-reviewed memory. It is READ-ONLY.

## Patterns (`search_patterns`)

Known false-positive and true-positive patterns with explicit matching logic.
A pattern match is only valid when:
- the pattern's `required_evidence` is actually present, AND
- none of its `invalidators` apply.

A known-FP pattern does NOT by itself prove a case is benign — confirm the
required evidence and rule out the invalidators first. Cite the matched pattern
name in your verdict's `matched_patterns`, and state what would invalidate it.

## Baselines (`list_baseline_entities` → `get_baselines`)

Per-subject behavioral windows. Before calling `get_baselines`, call
`list_baseline_entities` (with the relevant `subject_type`) to discover which
subject IDs are stored — this avoids misses caused by ID format differences
(e.g. FQDN vs. short hostname). Then call `get_baselines` for each matching entity.
Treat a deviation from baseline as a lead, not proof. Respect the `health` field:
`stale`, `low_data`, or `missing` baselines are weak evidence.

Available features and how to interpret them:

**Endpoints** (`subject_type: endpoint`):
- `common_rules` — top Wazuh rule IDs seen on this host. A rule ID appearing
  during an incident that is absent from `top_rules` is anomalous.
- `active_hours` — hour-of-day event histogram. Activity outside the normal hours
  (counts near zero in the histogram) is an anomaly signal.
- `common_users` — top `data.srcuser` values seen on this host. Any user account
  not in `top_users` interacting with this endpoint is a lateral-movement signal.
- `event_volume` — daily event count statistics (`daily_mean`, `daily_std`, `p5`,
  `p95`). Compare the current session's event count against `daily_mean ± daily_std`;
  a spike >2σ above mean suggests an attack or misconfiguration; a count near zero
  when the host is normally busy may indicate logging suppression.

**Users** (`subject_type: user`):
- `source_ips` — top source IPs this user logs in from. An unfamiliar source IP is
  a credential-theft or account-takeover signal.
- `active_hours` — same hour-of-day histogram; off-hours logins are anomalous.
- `event_volume` — same daily stats; a spike in user-attributed events may indicate
  automated credential spraying or lateral movement under that account.
- `auth_failure_rate` — `auth_events` (total authentication events), `auth_failures`,
  and `failure_rate` (failures ÷ total). A `failure_rate` significantly above the
  stored baseline supports a brute-force hypothesis. A rate near 1.0 with high volume
  is a strong brute-force indicator even without a confirmed successful login.

## Feedback (`search_feedback`)

Two modes:

**Same-case** (`case_id` provided): returns all corrections an analyst made on this
specific case. Always check this first — if an analyst already overturned a verdict
here, do not repeat it.

**Cross-case** (no `case_id`): returns recent analyst corrections across all cases.
Pass `rule_ids` to filter to entries that involved the same detection rules as the
current case. Each entry includes a `context` field with `rule_ids`, `users`, `hosts`,
and `alert_types` from the original case.

How to use cross-case feedback for verdict decisions:
- An entry where `analyst_verdict.verdict = "tp"` and `original_verdict.verdict = "fp"`
  means an agent previously thought this kind of alert was benign but an analyst
  disagreed. Treat this as a prior that similar alerts warrant deeper investigation —
  raise your suspicion and lower the threshold for `needs_investigation`.
- An entry where `analyst_verdict.verdict = "fp"` and `original_verdict.verdict = "tp"`
  means an agent over-escalated on a similar alert. Treat this as weak evidence toward
  benign, but still confirm the required evidence yourself.
- Cite matching feedback entries in `supporting_evidence` as
  `"feedback:<run_id> analyst=<verdict>"` so the verdict is traceable.

Never treat absence of a matching pattern or feedback as evidence of malice.
""",
                ),
            )
        ],
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search_patterns",
            description=(
                "Search curated FP/TP patterns. Returns enabled, non-expired patterns, "
                "optionally filtered by verdict ('tp'/'fp') and/or overlapping rule IDs. "
                "Each pattern lists its conditions, required_evidence, and invalidators."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["tp", "fp"]},
                    "rule_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        Tool(
            name="list_baseline_entities",
            description=(
                "List all distinct entities (subject_type + subject_id pairs) that have "
                "computed baseline snapshots. Call this first to discover which subjects "
                "have baselines before calling get_baselines — avoids guessing IDs that "
                "may not match the stored form. Optionally filter by subject_type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "subject_type": {"type": "string", "enum": ["endpoint", "user", "service"]},
                },
            },
        ),
        Tool(
            name="get_baselines",
            description=(
                "Get computed behavioral baselines for one subject. Returns each feature "
                "(active_hours, source_ips, sudo_users, ...) with its value and health "
                "(fresh/stale/missing/low_data). Use list_baseline_entities first to find "
                "the exact subject_id as stored."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "subject_type": {"type": "string", "enum": ["endpoint", "user", "service"]},
                    "subject_id": {"type": "string"},
                },
                "required": ["subject_type", "subject_id"],
            },
        ),
        Tool(
            name="search_feedback",
            description=(
                "Get analyst feedback/corrections. "
                "With case_id: returns all feedback for that specific case (no time or row limit). "
                "Without case_id: returns recent cross-case feedback ordered by most recently "
                "updated. Pass rule_ids to filter to entries whose case involved those rules — "
                "the most targeted way to learn from past corrections on similar alerts. "
                "Each entry includes a context field with the rule_ids, users, hosts, and "
                "alert_types from the original case, plus original_verdict and analyst_verdict "
                "showing what the agent said vs. what the analyst decided."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "rule_ids": {"type": "array", "items": {"type": "string"}},
                    "days": {"type": "integer", "default": 30},
                    "limit": {"type": "integer", "default": 20},
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "search_patterns":
            result = {
                "patterns": _store.search_patterns(
                    verdict=arguments.get("verdict"),
                    rule_ids=arguments.get("rule_ids"),
                )
            }
        elif name == "list_baseline_entities":
            result = {
                "entities": _store.list_baseline_entities(
                    subject_type=arguments.get("subject_type"),
                )
            }
        elif name == "get_baselines":
            result = {
                "baselines": _store.get_baselines(
                    arguments["subject_type"], arguments["subject_id"]
                )
            }
        elif name == "search_feedback":
            result = {"feedback": _store.search_feedback(
                case_id=arguments.get("case_id"),
                rule_ids=arguments.get("rule_ids"),
                days=arguments.get("days", 30),
                limit=int(arguments.get("limit", 20)),
            )}
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
