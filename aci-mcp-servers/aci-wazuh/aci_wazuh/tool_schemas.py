"""Tool schema definitions for the aci-wazuh MCP server (extracted from server.py)."""
from __future__ import annotations

from mcp.types import Tool


def wazuh_tools() -> list[Tool]:
        return [
            Tool(
                name="search",
                description=(
                    "Search Wazuh (OpenSearch) for security events. The `query` argument is "
                    "sent as the OpenSearch top-level query clause exactly as provided; the "
                    "tool does not add time filters, size limits, source filters, or other "
                    "postprocessing. Therefore every query MUST include a bool.filter "
                    "@timestamp range. Use {\"range\":{\"@timestamp\":{\"gte\":0}}} when no "
                    "time window is known. The filter clause is reserved for @timestamp only. "
                    "Start broad with should clauses over full_log, rule.description, and "
                    "rule.groups, then narrow. Do not use .keyword, query_string, scripts, "
                    "or match objects of the form {\"query\": ...}."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "object",
                            "description": (
                                "OpenSearch query clause sent unchanged under the search body's "
                                "top-level `query` key. Must normally be {\"bool\":{...}} with "
                                "`filter` containing only an @timestamp range. Use short-form "
                                "match, e.g. {\"match\":{\"full_log\":\"ssh\"}}. Wildcards must "
                                "set case_insensitive=true. Do not use `.keyword`, query_string, "
                                "scripts, or request-level keys such as time_range/max_results."
                            ),
                        },
                        "index_pattern": {
                            "type": "string",
                            "description": "Index pattern to search (default: WAZUH_INDEX_PATTERN env var).",
                        },
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="get_event",
                description=(
                    "Retrieve a specific Wazuh event by its OpenSearch document _id. The _id MUST "
                    "be one you obtained from a prior `search` result's '_id' field (a long opaque "
                    "string like 'ufZOUZYBcMy642XY-OMO'). Do NOT pass guessed/short ids or a "
                    "TheHive alert sourceRef — those are not valid document ids. If you don't have "
                    "a real _id yet, use `search` with field filters instead."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "event_id": {
                            "type": "string",
                            "description": "The OpenSearch document _id, taken verbatim from a search result.",
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                    "required": ["event_id"],
                },
            ),
            Tool(
                name="profile_field",
                description=(
                    "Profile a field: return its most common values and their counts (a terms "
                    "aggregation). Use this to understand the data and find pivots — e.g. top "
                    "source IPs, users, rule IDs, processes, or commands. Use the field name "
                    "directly (e.g. 'rule.id', 'agent.ip', 'data.srcuser', 'data.command'); Wazuh "
                    "fields are keyword and aggregate as-is — do NOT append '.keyword' (no such "
                    "subfield exists). Optionally scope with time_range or a query/filter."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "field": {
                            "type": "string",
                            "description": "Field to profile, e.g. 'agent.ip' or 'rule.id'.",
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "Number of top values to return (default 10, max 100).",
                            "default": 10,
                        },
                        "query": {
                            "description": "Optional OpenSearch DSL object or keyword string to restrict the docs profiled.",
                            "oneOf": [{"type": "object"}, {"type": "string"}],
                        },
                        "time_range": {
                            "type": "object",
                            "description": "Optional time window; prefer absolute ISO 8601 values from the alert data.",
                            "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                    "required": ["field"],
                },
            ),
            Tool(
                name="search_keyword",
                description=(
                    "Search for events using Discover-style free text across common Wazuh alert "
                    "fields, including full_log, rule, agent, user/IP, command, path, and file "
                    "fields. Use when you don't know the exact field — e.g. an IP, username, "
                    "filename, hash, or command. For field-specific queries use `search` instead."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Find events matching any space-separated query term across common Wazuh alert fields. Terms use Discover-style OR semantics.",
                        },
                        "time_range": {
                            "type": "object",
                            "description": "Optional time window; prefer absolute ISO 8601 values from the alert data.",
                            "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of events to return (default 20, max 100).",
                            "default": 20,
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="list_indices",
                description="List available Wazuh indices.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="get_index_schema",
                description="Get the field mapping (schema) for a Wazuh index pattern.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "index_pattern": {
                            "type": "string",
                            "description": "Index pattern (e.g. 'wazuh-alerts-*').",
                        }
                    },
                    "required": ["index_pattern"],
                },
            ),
        ]
