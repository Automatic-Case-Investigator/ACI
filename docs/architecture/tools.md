# MCP And Tool Policy

MCP tools are deny-by-default through each agent's `tool_policy`.

Built-in providers live under `agent/runtime/providers/` and resolve settings
through the provider config resolver. Additional MCP servers can be registered
through `MCPServerConfig` without editing the graph or runner. At run start, the
runtime injects `ACI_CASE_ID`, `ACI_RUN_ID`, and `ACI_AGENT_NAME` into configured
stdio MCP environments so queue-scoped servers can enforce platform-owned
identity.

### Standardized provider capability contract

Agents should reason about provider access through stable capability roles, not
by assuming one vendor's tool names. Built-in providers therefore declare a
capability map from a standardized role to one or more concrete MCP tools.

- Every `siem` provider must expose:
  `search_events`, `fetch_event`, `inspect_schema`, `profile_field_values`
- Every `soar` provider must expose:
  `read_case`, `list_case_alerts`, `read_alert`, `publish_case_report`
- Utility and filesystem providers can also advertise standardized roles such
  as queue writes, board writes, memory lookup, and workspace read/write.
- Providers also declare whether MCP instructions are required before their
  tools may be exposed for a run.

This keeps agent prompts vendor-neutral while still letting each MCP server
publish exact tool names, query syntax, and platform-specific usage rules in its
own MCP prompt guidance.

The graph applies one extra policy rule: `triage` does not expose `create_task`
to the model. Triage returns a report and proposed plan; the orchestrator decides
whether to start investigation, and the investigation agent converts the handoff
into its own queue work.

### SIEM Query Robustness (Wazuh)

`aci-mcp-servers/aci-wazuh/aci_wazuh/client.py` (`WazuhClient`) adds
deterministic guards around model-constructed query DSL, surfaced back to the
model as a `hint`/`note` on the tool result rather than failing silently:

- **Malformed-query hints.** `_query_error_hint` maps a known Elasticsearch
  parse failure (e.g. a `should` clause nested incorrectly) to one actionable
  correction instead of a raw stack trace.
- **Timestamp-in-keyword stripping.** `_strip_temporal_tokens` removes
  ISO-8601 tokens a model mistakenly placed inside `search_keyword` terms
  (timestamps belong in `time_range`); leaving them in forces the
  any-term fallback to match almost the whole index.
- **`should`-without-`must` detection.** `_has_noop_should` recursively
  scans a `bool` query for a `should` clause with no `must` and no
  `minimum_should_match`. Under Elasticsearch/OpenSearch defaults this shape
  is **scoring-only** — the query silently matches everything else in scope
  (commonly just the time-range `filter`) instead of being narrowed by the
  `should` terms. This is the most common way a query that *looks* narrow
  returns the whole window; `search()` attaches a `note` explaining the fix
  whenever it fires.

**Agent-name is not a guaranteed-unique identity.** A Wazuh `agent.name`
display label can be shared by multiple distinct monitored hosts (verified
live: 13 distinct `agent.id`/`agent.ip` values shared one `agent.name` in a
production dataset). Investigation and platform prompt guidance teach
verifying cardinality via `profile_field("agent.id", ...)` before treating
events scoped only by `agent.name` as one host's activity — the same
"confirm a field/value exists before filtering" methodology extended to
"confirm a grouping key is actually unique before merging by it."
