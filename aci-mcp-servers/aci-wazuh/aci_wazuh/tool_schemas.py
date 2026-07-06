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
                    "tool does not add time filters, source filters, or other postprocessing, "
                    "and returns up to `max_results` events (default 20). Therefore every query "
                    "MUST include a bool.filter "
                    "@timestamp range. Use {\"range\":{\"@timestamp\":{\"gte\":0}}} when no "
                    "time window is known. The filter clause is reserved for @timestamp only. "
                    "Start broad with should clauses over full_log, rule.description, and "
                    "rule.groups, then narrow. Do not use .keyword, query_string, scripts, "
                    "or match objects of the form {\"query\": ...}. The result includes "
                    "`clause_diagnostics`: for each must/should clause, how many documents in "
                    "the time window match THAT clause alone. Read it to see which discriminator "
                    "is selective and which is a flood — a clause matching ~all `window_docs` "
                    "narrowed nothing, and if only one clause is selective your conjunction "
                    "rests on it. It does NOT prove co-occurrence: to confirm a joint fact "
                    "(user X authenticated FROM ip Y) the events must satisfy the clauses "
                    "TOGETHER (a must-conjunction), which is the query `total`, not a per-clause "
                    "count. An over-broad result also carries `rule_groups_breakdown` — the "
                    "behaviour-class composition of the flood; an entity-only query returns the "
                    "union of all the entity's classes, so scope to the `rule.groups` class your "
                    "objective needs (or `must_not` the dominant one shown) to escape it."
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
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of events to return (default 20, max 100).",
                            "default": 20,
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
                    "Profile a field's values and counts (a terms aggregation). By default "
                    "returns the most COMMON values — use it to understand the data and find "
                    "pivots (top source IPs, users, rule IDs, processes, commands). With "
                    "`rare=true` it instead returns the LEAST common values (the long tail a "
                    "top-N view hides): in a high-volume window the common head is background "
                    "noise, while a low-frequency value — a rule that fired a handful of times, "
                    "a single anomalous user/path/destination — is where an intrusion surfaces. "
                    "Use the field name directly (e.g. 'rule.id', 'agent.ip', 'data.srcuser'); "
                    "Wazuh fields are keyword and aggregate as-is — do NOT append '.keyword'. "
                    "Optionally scope with time_range or a query/filter."
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
                            "description": "Number of values to return (default 10, max 100). In rare mode, the count of rarest values returned.",
                            "default": 10,
                        },
                        "rare": {
                            "type": "boolean",
                            "description": "When true, return the LEAST common values (long tail) instead of the most common. Use to find low-frequency anomalies in a noisy/high-volume window. Point this at a low-cardinality categorical/keyword field (rule.id, data.url, data.srcuser, data.srcip, agent.name, a path/command) — NOT a free-text field like full_log, which cannot be aggregated.",
                            "default": False,
                        },
                        "max_doc_count": {
                            "type": "integer",
                            "description": "Rare mode only: a value counts as rare if it appears in at most this many docs (default 10, max 100). Raise to widen the rare band.",
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
                    "Search for events by free-text keywords across common Wazuh alert "
                    "fields, including full_log, rule, agent, user/IP, command, path, and file "
                    "fields. All terms must match (AND), so adding more distinctive terms "
                    "narrows the results; if nothing matches all terms it falls back to an "
                    "any-term match and flags the result as broadened. Use when you don't know "
                    "the exact field — e.g. an IP, username, filename, hash, or command. For "
                    "field-specific queries use `search` instead."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Space-separated keywords matched across common Wazuh alert fields. All terms must match (AND) — add distinctive terms (host, command, path fragment, IP, file) to narrow. Falls back to any-term match only when nothing matches all terms.",
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
                name="correlate_entity",
                description=(
                    "Return the grounded correlation neighborhood of a CONFIRMED entity "
                    "(IP, user, host, process, file, or rule). In ONE call it pins "
                    "field=value and profiles every other dimension that co-occurs with "
                    "it — users, hosts, source/destination IPs, processes, files, rule "
                    "families — each neighbor carrying a count, first/last seen, and a "
                    "few sample event _ids you can cite. This replaces issuing many "
                    "separate profile_field/search calls and joining them by hand. For an "
                    "IP entity it also correlates the SAME value in the opposite network "
                    "role (returned under `cross_role`), answering 'is this callback "
                    "destination also a login source?' in one shot. Use this as the FIRST "
                    "pivot after confirming any entity, before manual per-field queries. "
                    "It tells you which events matter; retrieve full events with `search`/"
                    "`get_event` to quote evidence — do not cite a neighbor bucket as an event."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "field": {
                            "type": "string",
                            "description": "The confirmed entity's field, e.g. 'data.srcip', 'data.srcuser', 'agent.name', 'rule.id'. Use the field name directly (no '.keyword').",
                        },
                        "value": {
                            "type": "string",
                            "description": "The confirmed value to pin, taken from real event data (e.g. an IP, username, hostname).",
                        },
                        "start_time": {
                            "type": "string",
                            "description": "Window start as ISO 8601; strongly recommended to keep the neighborhood focused. Omit only for an all-history scan.",
                        },
                        "end_time": {
                            "type": "string",
                            "description": "Window end as ISO 8601.",
                        },
                        "link_fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional explicit neighbor dimensions to profile. Omit to use the curated default set.",
                        },
                        "match_fields": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional: match `value` in ANY of these fields instead of just `field` (e.g. ['data.srcuser','data.dstuser'] so a user is found regardless of role). When given, the cross_role view is omitted because both roles are already covered.",
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "Top values to return per neighbor dimension (default 10, max 50).",
                            "default": 10,
                        },
                        "min_cooccurrence": {
                            "type": "integer",
                            "description": "Drop neighbor values seen in fewer than this many events (default 1 = keep all). Raise to suppress noise.",
                            "default": 1,
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                    "required": ["field", "value"],
                },
            ),
            Tool(
                name="correlate_techniques",
                description=(
                    "Aggregate the MITRE ATT&CK techniques observed in a window into a "
                    "kill-chain view. Groups events by `rule.mitre.id` with the technique "
                    "name, tactic(s), counts, and sample event _ids, plus a tactic "
                    "histogram. Use it to see the attack at the adversary-behavior level — "
                    "which tactics (Initial Access, Execution, Persistence, Privilege "
                    "Escalation, Credential Access, Lateral Movement, Command and Control, "
                    "Exfiltration, Impact) have evidence and which are GAPS to investigate "
                    "or rule out. Scope with a query (e.g. {\"term\":{\"agent.name\":\"<host>\"}}) "
                    "so the techniques describe one incident, not the whole environment."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_time": {"type": "string", "description": "Window start (ISO 8601)."},
                        "end_time": {"type": "string", "description": "Window end (ISO 8601)."},
                        "query": {
                            "description": "Optional scope: an OpenSearch DSL object (e.g. a host term) or a keyword string.",
                            "oneOf": [{"type": "object"}, {"type": "string"}],
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "Max distinct techniques to return (default 30, max 100).",
                            "default": 30,
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                },
            ),
            Tool(
                name="get_event_volume",
                description=(
                    "Return a time histogram of matching event counts across a window "
                    "(an OpenSearch date_histogram on @timestamp). Use this to see HOW "
                    "event volume changes over time rather than what the top values are: "
                    "confirm a brute-force burst and find when it stops (often the "
                    "successful-login moment), detect regularly-spaced beaconing/C2, "
                    "bound the active attack window before narrowing other pivots, and "
                    "spot quiet temporal gaps. Empty bins are returned with count 0 so "
                    "gaps are visible. Cheaper than paging raw events when you only need "
                    "the volume curve. Provide an absolute start_time and end_time; "
                    "optionally restrict with a query and set the bin granularity."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_time": {
                            "type": "string",
                            "description": "Window start as ISO 8601 (e.g. '2026-06-28T00:00:00Z'); prefer absolute values from the case/alert.",
                        },
                        "end_time": {
                            "type": "string",
                            "description": "Window end as ISO 8601. Buckets cover start_time..end_time inclusive.",
                        },
                        "query": {
                            "description": "Optional filter: an OpenSearch DSL object (e.g. {\"term\":{\"data.srcip\":\"1.2.3.4\"}}) or a free-text keyword string matched across common alert fields. Omit to count all events in the window.",
                            "oneOf": [{"type": "object"}, {"type": "string"}],
                        },
                        "interval": {
                            "type": "string",
                            "description": "Bin width as an OpenSearch fixed_interval (e.g. '5m', '1h', '1d'). If omitted, the window is split into `bins` equal buckets.",
                        },
                        "bins": {
                            "type": "integer",
                            "description": "Target number of buckets when `interval` is not given (default 24, max 1000).",
                            "default": 24,
                        },
                        "index_pattern": {"type": "string", "description": "Index pattern (optional)."},
                    },
                    "required": ["start_time", "end_time"],
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
