# Findings Board

`aci-board` stores per-run Findings Board entries of seven kinds. `fact` and
`hypothesis` are populated by parsing the model's own report sections; the
remaining five are populated deterministically by the `use_tools` enrichment
pipeline, with no model call involved in writing them:

| Kind | Meaning | Population |
|---|---|---|
| `artifact` | A normalized entity observed in a retrieved native event, including a payload decoded from hex/base64/URL-encoding. | Deterministic extraction (`agent/runtime/analysis/artifacts.py`) after every successful investigation tool result. |
| `fact` | A confirmed, evidence-backed finding. | Structural parsing of `## Findings`, gated by the [per-task self-review](runtime/agent-graph.md#per-task-self-review)'s grounded/novel verdicts — only bullets the review confirms are new and event-cited become facts. |
| `hypothesis` | An explanation or lead requiring confirmation or refutation. | Structural parsing of `## Hypotheses`, triage handoff hypotheses, and generated leads. |
| `correlation` | A confirmed entity's co-occurring neighborhood (other entities, fields, sample event IDs). | Deterministic, automatic — `_auto_correlate_entities` fires `correlate_entity` for newly confirmed high-value entities without a model call. |
| `kill_chain` | The MITRE ATT&CK tactic/technique coverage observed so far, plus detected gaps. | Deterministic, automatic — `_build_kill_chain` (`agent/runtime/analysis/kill_chain.py`) fires `correlate_techniques` and can queue gap-coverage follow-up tasks. |
| `query_memo` | A record of a SIEM query shape that returned an unusably broad/truncated result. | Deterministic — `agent/runtime/analysis/query_memo.py`, so later tasks see it and avoid reissuing the same broad shape. |
| `ti_result` | Threat-intelligence enrichment for a confirmed artifact (e.g. VirusTotal verdict). | Deterministic, async, rate-limited (`agent/ti/enricher.py`); optional, only when a TI provider is configured. |

Artifact extraction does not ask the model to recognize entities and does not
invoke a board MCP tool. Only allow-listed event fields are accepted. Nested
Elasticsearch/Wazuh shapes are flattened, values are validated and normalized,
and entries retain the native event ID as their source. Recognized types
include event IDs, IPs, MD5/SHA1/SHA256 hashes, domains, hosts, users,
processes, file paths, and **decoded commands** — long hex/base64/URL-encoded
tokens are decoded and re-scanned for compromise-indicator patterns (e.g. a
reverse-shell one-liner hidden in a base64 URL parameter), independent of
whether the agent itself thought to decode the value.

Before each non-seed investigation task, the graph injects the full Findings
Board into model context:

- artifacts are proposed as pivots, and decoded-command artifacts are
  retrieved evidence the agent must surface, not re-derive;
- facts are treated as established unless newer evidence contradicts them;
- hypotheses must be tested, refined, confirmed, refuted, or left explicitly
  unresolved.

**Board-driven compromise detection.** The `interpret` must-disposition block,
escalation (an immediate case comment when active compromise is confirmed), and
the per-task self-review's `unreported_compromise_artifacts` signal all read
compromise-relevant evidence directly off the board (`agent/runtime/graph/
validation.py: _board_compromise_facts`) rather than relying on the agent's own
narrative to mention it. Two deterministic triggers surface an entry: a narrative
reverse-shell / C2 indicator, **or** any command the decode layer recovered from an
encoded field (marked `[decoded]`/`[hex-decoded]`). The decode marker is
technique-agnostic on purpose — a `mysql ... select * from wp_users` credential
dump or an offline password-cracker invocation is surfaced the same as a
`/dev/tcp/...` reverse shell; the code only asserts "an attacker hid a command
here, account for it," and the model classifies the kill-chain phase in context (it
has the full board). Decoded commands are ranked ahead of narrative matches so the
deterministic ground truth is never crowded out of the interpret block's cap. The
board's decoded artifact is authoritative regardless of whether the agent's own
search for that indicator happens to return a hit — a confirmed decode is evidence
on its own.

The final investigation summary includes the structural categories before task
summaries. This lets the orchestrator understand both accumulated knowledge and
the state of unresolved reasoning across the run.
