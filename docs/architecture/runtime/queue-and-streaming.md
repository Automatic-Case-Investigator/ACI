# Queue Semantics & Model Streaming

## Queue Semantics

`aci-taskqueue` is the execution authority. The graph never decides which task is
next locally; it calls `claim_next`, which uses a SQLite `BEGIN IMMEDIATE`
transaction to claim the highest-priority pending task across MCP subprocesses.

Human edits are hard state changes. Queue API writes update the same task store
that agents claim from, so an analyst priority change or dismissal affects the
next claim boundary.

Completion is queue-driven. A model response does not finish a run by itself; it
only completes the current task. The graph returns to `claim` until the queue is
empty, cancellation is requested, or step/tool-call budgets are exhausted.

The task lifecycle beyond claiming — the completion contract, per-task self-review,
and the seeder agent that populates the queue — is covered under
[Runtime & Agent Graph](agent-graph.md#task-completion-contract).

### Task Store Internals

`aci-mcp-servers/aci-taskqueue/aci_taskqueue/store.py` is a small, dependency-free
SQLite store (standard-library `sqlite3`, no ORM) — deliberately simple since its
only job is atomic claim ordering, not general persistence:

- **Schema.** One `tasks` table per `TASKQUEUE_DB_PATH` database, scoped by
  `(case_id, run_id, agent_name)` — the same three-part identity the runtime injects
  into every configured stdio MCP subprocess's environment (`ACI_CASE_ID`,
  `ACI_RUN_ID`, `ACI_AGENT_NAME`), so a case with both a triage and an investigation
  run never share a queue. A composite index
  `(case_id, run_id, agent_name, status, priority)` backs both `list_tasks` and
  `claim_next`.
- **Ordering.** Every read (`list_tasks`, `claim_next`) sorts `priority DESC,
  created_at ASC` — highest priority first, ties broken FIFO. `reorder(ordered_ids)`
  imposes an explicit analyst-chosen order by rewriting priorities to `(n - idx) *
  10` (spaced by 10 so a later insert can be prioritized between two existing tasks
  without a full renumber); tasks not named in `ordered_ids` keep their current
  priority and sort after the reordered set.
- **Claim atomicity.** `claim_next` wraps its select-then-update in
  `BEGIN IMMEDIATE` (an immediate write lock, not a plain read) plus a
  process-local `threading.Lock`, and every connection sets
  `PRAGMA busy_timeout = 5000` — the database file is shared between the Django
  process and the agent's own MCP subprocess, so a lock conflict waits up to 5s for
  the other side rather than failing immediately. This is what makes "claim the
  highest-priority pending task" safe even though two different OS processes can
  both be reading and writing the same SQLite file.
- **Model-visible task shape.** `agent_visible_task` strips queue-lifecycle
  timestamps (`created_at`, `updated_at`, `claimed_at`) from what's shown to the
  model — those fields drive ordering and dashboard UI, but are not investigative
  evidence and would just be noise (or a hallucination hazard) in a task payload.
- **Lifecycle.** `pending -> claimed -> {completed | failed | dismissed}`, or back to
  `pending` via `reopen_task`. `complete_task` refuses an empty summary
  (`ValueError`) at the store layer — the same non-empty-summary rule the graph's
  [Task Completion Contract](agent-graph.md#task-completion-contract) enforces one
  level up, so a blank completion can't slip through even if a future caller
  bypasses the graph's own recovery-call logic.
- **`claim_next` and `complete_task` are graph-managed, never model-exposed.**
  `_model_tools_for_agent` (`agent/runtime/graph/toolio.py`) unconditionally strips
  both from the tool list handed to the model, for both agents: `claim` (the graph
  node) owns claiming and `assess` owns completion (always with a non-empty
  summary). If the model could call `claim_next` itself it could mark a task
  claimed without doing the work — the queue would look empty while nothing was
  actually investigated; `complete_task` has the same risk in reverse, letting the
  model close out a task mid-investigation before any real work happened.
  `create_task` is excluded the same way for **both** `triage` and `investigation`
  — task creation goes through the seeder (at seed time) and the `pivot` node (for
  new leads) described in
  [Runtime & Agent Graph](agent-graph.md#seeder-agent), never a direct model call.

## Live Model Streaming

Model calls use LangChain streaming when the provider supports `astream`.
`agent.runtime.streaming.invoke_streaming` emits each provider text delta as a
`stream` event while accumulating the final `AIMessageChunk` so existing
tool-call and assessment logic still receives a normal final model message.

Transient deltas bypass the `AgentEvent` database writer. The runner appends them
to a thread-safe per-session buffer, and `RunConsumer` drains that buffer every
50 ms from the ASGI event loop before forwarding the deltas over WebSocket.

`static/dashboard/app.js` merges consecutive stream deltas from the same
source/run into a single live assistant bubble. When the orchestrator emits the
final persisted `answer` event, the browser finalizes that bubble instead of
rendering a duplicate answer.

Tool-call chunks are preserved by LangChain chunk addition. Chunks without text
still contribute to the accumulated final message but do not create visible
stream events.
