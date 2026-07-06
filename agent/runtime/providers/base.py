"""Provider abstraction for MCP servers (SOAR / SIEM / utility / filesystem).

A provider describes one MCP server: its stable `key` (matched against an agent's
`tool_policy`), its `kind`, and two callables:

- `setting_defaults()` pulls this server's connection fields from django settings
  (the env-backed source of truth today).
- `build_config(resolved, run_ctx)` turns a resolved settings dict (DB overrides
  merged over the defaults by `runtime/config.py`) into the MCP server config
  consumed by `MultiServerMCPClient`. `run_ctx` carries the current run's identity
  (case_id/run_id/agent_name) so a provider can scope its subprocess to that run;
  it is None when the client is built outside a specific run.

Adding a new MCP platform = drop a module in this package that registers a provider.
No edits to `mcp_client.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

# Kinds mirror agent/models.py:ProviderConfig.KIND_* so admin + registry agree.
KIND_SOAR = "soar"
KIND_SIEM = "siem"
KIND_UTILITY = "utility"
KIND_FILESYSTEM = "filesystem"

CAPABILITY_DOCS: dict[str, dict[str, str]] = {
    "search_events": {
        "label": "Search raw events",
        "description": "Run bounded searches for raw SIEM events using explicit time scope and pivots.",
    },
    "fetch_event": {
        "label": "Fetch one event",
        "description": "Retrieve one raw SIEM event by its native event/document identifier.",
    },
    "inspect_schema": {
        "label": "Inspect schema",
        "description": "Discover available indices, fields, or schemas before guessing field names.",
    },
    "profile_field_values": {
        "label": "Profile field values",
        "description": "Summarize top values for a SIEM field within a bounded scope.",
    },
    "quick_search": {
        "label": "Quick broad search",
        "description": "Run a low-friction text-first sweep before building narrow structured queries.",
    },
    "correlate_entity": {
        "label": "Correlate entity",
        "description": "Expand a confirmed artifact into related entities and co-occurrences.",
    },
    "summarize_volume": {
        "label": "Summarize event volume",
        "description": "Bucket event counts across time to spot bursts, gaps, or spread.",
    },
    "read_case": {
        "label": "Read case",
        "description": "Load the canonical case record, analyst context, and case metadata.",
    },
    "list_case_alerts": {
        "label": "List case alerts",
        "description": "Enumerate or summarize the alerts linked to a case.",
    },
    "read_alert": {
        "label": "Read alert",
        "description": "Retrieve one full alert record for pivots and source details.",
    },
    "publish_case_report": {
        "label": "Publish case report",
        "description": "Write the final grounded report back into the SOAR case.",
    },
    "find_related_cases": {
        "label": "Find related cases",
        "description": "Retrieve cases linked by shared entities or prior similarity.",
    },
    "update_case_fields": {
        "label": "Update case fields",
        "description": "Modify SOAR case metadata such as severity, status, assignee, or tags.",
    },
    "post_case_note": {
        "label": "Post case note",
        "description": "Add an analyst-visible note or interim update to the SOAR case.",
    },
    "queue_read_tasks": {
        "label": "Read queued work",
        "description": "List or inspect task queue work owned by the current run.",
    },
    "queue_write_tasks": {
        "label": "Write queued work",
        "description": "Create, update, claim, or complete run-scoped task queue entries.",
    },
    "board_read_findings": {
        "label": "Read findings board",
        "description": "List grounded findings and hypotheses already recorded for the run.",
    },
    "board_write_findings": {
        "label": "Write findings board",
        "description": "Add or update grounded board entries for findings, hypotheses, or evidence.",
    },
    "memory_lookup": {
        "label": "Lookup memory",
        "description": "Search curated memory such as feedback, patterns, baselines, or prior lessons.",
    },
    "workspace_read_write": {
        "label": "Workspace files",
        "description": "Read and write case workspace files and supporting artifacts.",
    },
}

REQUIRED_CAPABILITIES_BY_KIND: dict[str, tuple[str, ...]] = {
    KIND_SIEM: ("search_events", "fetch_event", "inspect_schema", "profile_field_values"),
    KIND_SOAR: ("read_case", "list_case_alerts", "read_alert", "publish_case_report"),
}

OPTIONAL_CAPABILITIES_BY_KIND: dict[str, tuple[str, ...]] = {
    KIND_SIEM: ("quick_search", "correlate_entity", "summarize_volume"),
    KIND_SOAR: ("find_related_cases", "update_case_fields", "post_case_note"),
}


@dataclass(frozen=True)
class MCPProvider:
    key: str
    kind: str
    setting_defaults: Callable[[], dict]
    build_config: Callable[[dict, Optional[dict]], dict]
    default_enabled: bool = True
    capabilities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    instructions_required: bool = True

    def missing_required_capabilities(self) -> tuple[str, ...]:
        required = REQUIRED_CAPABILITIES_BY_KIND.get(self.kind, ())
        return tuple(cap for cap in required if not self.capabilities.get(cap))


def format_provider_capability_contracts(provider_keys: list[str]) -> str:
    from .contracts import format_provider_capability_contracts as _format

    return _format(provider_keys)


def provider_contract_snapshot(provider: MCPProvider) -> dict:
    from .contracts import provider_contract_snapshot as _snapshot

    return _snapshot(provider)
