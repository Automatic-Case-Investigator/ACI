# ACI Backend — M0

Free-form SOC investigation agents driven by a queue-based LangGraph loop.
`triage` and `investigation` agents are registered through `agent/agents/`, use
MCP tools through provider policies, and store durable work in AVFS.

For the detailed runtime design and graph diagram, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Quick start (local, no Docker)

```bash
cd ACI_Backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e aci-mcp-servers/aci-wazuh
pip install -e aci-mcp-servers/aci-taskqueue
pip install -e aci-mcp-servers/aci-thehive
pip install -e aci-mcp-servers/aci-board

cp sample.env .env
# Edit .env: set LLM_*, WAZUH_*, AVFS_*

python manage.py migrate
```

Migration `0006_agentevent_metadata` is required for intent stream correlation.

## Run AVFS (Docker Compose)

AVFS runs as a container; the backend talks to it over HTTP. Compose reads the
`AVFS_*` values from your `.env`, so configure those first (set a real
`AVFS_AUTH_TOKEN` — the literal `change-me-avfs-token` keeps AVFS disabled).

```bash
docker compose up -d avfs      # start (data persists in the avfs_data volume)
docker compose logs -f avfs    # tail logs
docker compose down            # stop
```

<details>
<summary>Equivalent raw <code>docker run</code></summary>

```bash
docker run --rm -p 8765:8765 -v avfs_data:/data \
  -e AVFS_SERVER__TRANSPORT=http \
  -e AVFS_SERVER__HOST=0.0.0.0 \
  -e AVFS_AUTH__MODE=static_token \
  -e "AVFS_AUTH__STATIC_TOKENS__<your-token>=agent_1" \
  -e AVFS_RELATIONAL_DB__URI=avfs+sqlite:///data/avfs.db \
  1bd08a0df278/avfs:latest
```
</details>

## Run the agent (CLI)

```bash
python manage.py run_agent \
  --agent-name investigation \
  --case-id demo-001 \
  --question "Were there any failed SSH login attempts in the last 24 hours?"
```

## REST API

```
POST /api/agent/runs/
  { "agent_name": "investigation", "case_id": "demo-001", "question": "..." }
→ { "run_id": "...", "status": "queued" }

GET /api/agent/runs/<run_id>/
→ { "run_id": "...", "status": "completed", "result": "..." }

GET /api/agent/runs/<run_id>/status/
GET /api/agent/runs/<run_id>/events/
POST /api/agent/runs/<run_id>/cancel/
POST /api/agent/runs/<run_id>/resume/

GET   /api/agent/cases/<case_id>/queues/<agent_name>/tasks/?run_id=<run_id>
POST  /api/agent/cases/<case_id>/queues/<agent_name>/tasks/
PATCH /api/agent/cases/<case_id>/queues/<agent_name>/tasks/

GET /api/agent/cases/<case_id>/workspace/
GET /api/agent/cases/<case_id>/reports/latest/
```

Authentication: JWT via `POST /api/token/` (Django user credentials).

## Modular runtime contracts

- Agents are `AgentDefinition` records registered in `agent/agents/registry.py`.
  Duplicate names are rejected at import time.
- MCP tools are deny-by-default. Built-in providers live under
  `agent/runtime/providers/`; external MCP servers can be added through
  `MCPServerConfig` without editing the runner.
- The OpenAI-compatible model client uses `ModelProviderConfig(id="default")`
  when present and falls back to `LLM_*` environment settings.
- Model requests have no client-side timeout by default. Set `LLM_TIMEOUT` or
  `ModelProviderConfig.timeout` to a positive number of seconds only when an
  explicit request deadline is desired; blank or `0` means disabled.
- Runs use the fixed lifecycle statuses: `created`, `queued`, `running`,
  `waiting`, `completed`, `incomplete_budget`, `cancelled`, `blocked`, `failed`.
- Cancellation is honored at task-claim boundaries. Resume restarts the same run
  against the remaining task queue.
- Completed tasks always have a non-empty summary. If the action model returns no
  final message, the runtime requests a grounded completion recap from the task
  history. If that also returns nothing, it records a transparent tool-execution
  summary or explicitly states that no result was supplied.
- Before a tool-capable action, the runtime streams a public reasoning summary,
  persists it, and only then emits and executes the tool call. The narrative
  explains established state, current interpretation, uncertainty, and intended
  action without exposing private chain-of-thought.

## Live reasoning event contract

The dashboard receives the public reasoning summary in this order:

```text
intent_delta... -> intent -> call -> result
```

`intent_delta` is streamed in real time and is transient. The completed `intent`
event is stored in `AgentEvent` with an `intent_sequence` correlation value.
Triage and investigation summaries appear inside the relevant agent trace, while
final orchestrator response tokens remain in the assistant answer bubble.

If intent generation returns no text or fails, the runtime emits no replacement
intent and continues to the action model.

The narrative is free-form Markdown rather than a fixed schema. It may use short
paragraphs, bullets, emphasis, inline code, or brief headings. It communicates
useful conclusions and considerations, not raw hidden chain-of-thought,
token-level reasoning, or exhaustive internal deliberation. The contract is
independent of domain, task type, capability set, and execution environment.

Automatic workflows triggered by new cases or alerts remain future work. The
intent implementation is placed in the shared graph so those future headless runs
can reuse it without changing MCP tools or agent definitions.

## Findings Board

Each investigation run has a Findings Board containing:

- `artifact`: normalized entities observed in retrieved native events;
- `fact`: evidence-backed confirmed findings;
- `hypothesis`: open, confirmed, or refuted explanations and investigative leads.

Artifacts are not added by the model. After each successful investigation tool
result, the backend parses event-shaped JSON and deterministically extracts
allow-listed fields including native event IDs, IP addresses, hashes, domains,
hosts, users, processes, and file paths. Each entry retains the native event ID
as its source and is deduplicated by type and normalized value.

The complete Findings Board is injected into every non-seed investigation task.
The agent must use artifacts as pivots, build on confirmed facts, and test,
refine, confirm, or refute applicable hypotheses.

Confirmed facts are parsed from `## Confirmed Facts`. Hypotheses are parsed from
`## Hypotheses`, and each automatically generated investigation lead is also
recorded as an open hypothesis. These structural updates do not depend on the
model choosing a board tool.

## AVFS workspace indexing

All durable AVFS writes must go through the backend workspace writer or the graph
write hook. Each writable directory receives a `memory.md` index with:

- `# Memory`
- `## Purpose`
- `## Files`
- `## Child Directories`
- `## Notes`

When a file is written, the nearest directory index and parent indexes up to the
case/run/memory root are updated. Parent indexes summarize child directories
rather than duplicating every nested file. Citation validation lives in
`agent/workspace/citations.py` and fails closed when a factual citation points to
missing evidence.

## M0 success criteria

See `restart/CHARTER.md` §M0. The run passes when:

1. The model is called with native tool-calling (`tool_calls` populated).
2. At least one `aci-wazuh` tool returns real data from live Wazuh.
3. At least one AVFS write confirms evidence is stored.
4. The loop terminates within budget (≤20 steps).
5. The final answer cites information actually retrieved.

## Local verification

On macOS, the checked-in `venv/` may be a Windows-style environment. Use a local
or temporary Python 3.12 environment for checks:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e aci-mcp-servers/aci-taskqueue \
  -e aci-mcp-servers/aci-wazuh \
  -e aci-mcp-servers/aci-thehive \
  -e aci-mcp-servers/aci-board

python manage.py check
python tests/test_agent_contracts.py
python tests/test_graph_stub.py
python tests/test_streaming.py
python tests/test_intent_ordering.py
python tests/test_findings_board.py
python tests/test_avfs_expand.py
python tests/test_leads_re.py
```
