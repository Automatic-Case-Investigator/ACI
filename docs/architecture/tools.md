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

### Case-Write Authorization (Two Layers)

Posting to, closing, or otherwise mutating a SOAR case is treated as a distinct,
higher-stakes capability than reading it — gated at two separate points so it can
never happen without either explicit design intent (graph) or an explicit analyst
request in the moment (orchestrator):

1. **Graph tool policy (`_model_tools_for_agent`,
   `agent/runtime/graph/toolio.py`)** unconditionally strips the write tool set
   (`post_case_report`, `update_case`, `close_case`, `resolve_case`,
   `add_case_comment`, `post_case_comment` — `_CASE_WRITE_TOOLS`) from what the
   **investigation** agent's model can call, on every task, with no exception. The
   investigation agent posts its final report through the graph's own
   `publish_finish` node (see [Runtime & Agent Graph](runtime/agent-graph.md)), not
   by the model deciding to call a write tool mid-investigation — the concern is a
   model that follows an MCP server's own instructions (which may say "post a
   report when done") and writes prematurely or repeatedly.
2. **Orchestrator write gate (`agent/runtime/orchestrator/driver.py`)** applies the
   same `_CASE_WRITE_TOOLS` set to its own tool-bound model call, but conditionally:
   the tools are only exposed when the analyst's current message matches an
   explicit write-intent phrase (`_WRITE_PHRASES`, a regex over words like "post",
   "close", "update the case", etc. — case-insensitive). Without a matching phrase,
   `write_authorized` is `False` and the write tools are simply absent from that
   turn's tool list, so the model cannot call them regardless of what an MCP
   server's guidance suggests.

The two gates protect different actors — the investigation agent can never write
autonomously; the orchestrator can, but only when the human just asked for it in
that turn — and neither depends on prompt instructions alone, since MCP guidance is
untrusted input the model should not be able to leverage into an unauthorized
write.

### Integration Connections: Many Per Provider, One Active

A built-in provider's connection settings (Wazuh, TheHive, VirusTotal) are not a
single fixed value. An operator registers **one or more named connections per
provider** (e.g. a prod and a lab Wazuh) through Settings → Integrations, and marks
exactly one **active** per provider. The active connection is what the runtime
resolves into the live MCP subprocess or API client.

- **Model:** `IntegrationConnection` (`agent/models/config.py`) — `name`,
  `provider_key`, a `settings` JSON blob shaped by that provider's connection
  schema, and `is_active`. The single-active-per-provider invariant is enforced in
  the settings views (create/activate/delete), not by a database constraint.
- **Resolution order**, lowest to highest precedence, in
  `resolve_settings(key, defaults)` (`agent/runtime/config/__init__.py`):

  ```text
  .env / built-in defaults  <  ProviderConfig.settings (per-provider fallback)  <  active IntegrationConnection
  ```

  A provider with **zero** connections resolves from `ProviderConfig` and then
  `.env` alone — the active-connection layer only applies once a connection exists
  for that provider.
- **Consumers.** Every place that builds a live connection — the built-in
  provider's `build_config` (which shapes the MCP subprocess env/args), the
  Settings **Test** action, and automatic escalation's `TheHiveClient`
  (`agent/runtime/policy/escalation.py`, see
  [Workflows & Webhooks](automation.md#escalation-policy)) — goes through this
  same `resolve_settings` call, so there is exactly one place that decides which
  connection is "the" connection for a provider at any moment.
- **TheHive connection shape.** TheHive's connection settings are a single
  `base_url` field (e.g. `http://thehive:9000`). Both the MCP client
  (`aci-mcp-servers/aci-thehive/aci_thehive/client.py`) and the escalation
  `TheHiveClient` construction also accept a separate `host` + `port` pair as an
  alternate way to supply the same address, resolving to the identical base URL
  either way.

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
