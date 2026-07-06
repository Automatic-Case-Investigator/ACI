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

### Task Completion Contract

Every task stored with status `completed` must have a non-empty summary. When the
action model ends a task without text, `assess` performs one text-only recovery
call using the task conversation and tool results. The recovery prompt requires:

- work performed;
- key result or outcome;
- remaining uncertainty or blockers;
- relevant artifact paths or native event IDs.

If recovery also returns no text or fails, the runtime writes a deterministic
execution record derived from actual `ToolMessage` history. If there was no tool
activity, the record explicitly says that no findings or conclusion were
supplied. The taskqueue repository rejects direct blank completion summaries.

Investigation finalization reads these task summaries into the structured run
result, so the orchestrator can distinguish completed work, incomplete work, and
tasks that completed without a substantive conclusion.

### Per-Task Self-Review

Older revisions enforced task quality with a fixed cascade of separate guard
nodes (a triage-SIEM-query guard, an investigation-SIEM-query guard, a
broad-query guard, a depth guard, a summary-format guard, and an
incomplete-pivot guard), each hand-coding one failure mode as a Python
`if`-branch with its own retry counter. Per the design philosophy's
"prefer prompts and reusable workflow over edge-case branching", this was
replaced with a single **per-task self-review** (`agent/runtime/graph/reflection.py:
review_task_model`): one model call that judges the task holistically and
returns a `TaskReview` (`conclude` or `keep_working`, plus per-`## Findings`
bullet grounding/novelty verdicts).

The review is given deterministic *signals* to ground its judgment, computed in
code rather than guessed by the model:

- `evidence_queries` — count of genuine evidence-retrieval tool calls this task;
- `hit_count` / `hit_ceiling` — whether the most recent search result is at or
  near the unusable result ceiling;
- `unpivoted_iocs` — confirmed network indicators with no corresponding
  `## New Leads` pivot;
- `unqueried_clusters` — `get_event_volume` post-peak activity windows that
  were profiled but never followed up with a raw query;
- `unreported_compromise_artifacts` — confirmed compromise indicators already
  on the Findings Board (e.g. a decoded reverse-shell command) that are not
  yet reflected in this task's `## Findings`.

`assess` re-injects the review's feedback as one consolidated correction and
sets `status="needs_more_work"`, which `_route_assess` (`graph/builder.py`)
routes back to `think` if budget remains. `reflection_retries` bounds the
loop (default 2 retries); a **convergence guard**
(`reflection_evidence_at_last_nudge`) suppresses a further nudge if the prior
correction produced no new evidence query, so a task cannot churn forever on
orientation-only turns. The review is fail-open: if the model is unavailable
or the call fails, the task falls back to the deterministic non-empty-summary
check below and completes rather than stalling the run.

### Seeder Agent

A normal triage-handoff seed (i.e. not a resume) populates the investigation
queue through the dedicated `seeder` agent (`agent/runtime/engine/seeder_runner.py:
run_seeder`) instead of asking the investigation model to call `create_task`
directly. Seeding is two-phase:

1. **Deterministic extraction.** Plan items are parsed straight out of the
   triage report's `## Investigation Plan` and written with direct
   `create_task` calls — no model involvement. This guarantees exactly one
   task per plan item regardless of model behavior, which is what the old
   "seed guard" used to have to re-prompt for.
2. **Model pass for gaps.** A bounded second pass lets the model add tasks the
   plan may have omitted (e.g. an explicit C2-destination pivot or
   initial-access-vector task) and verify completeness via `list_tasks`.
   Every `create_task` call in this pass — direct or model-proposed — is
   checked against a **deterministic dedup backstop**
   (`agent/runtime/graph/leads.py: duplicate_existing_task`, the same matcher
   the pivot node's lead validator uses) before it is executed, so the model
   cannot queue two near-identical tasks in the same seeding pass.

`seeder` is `orchestrator_routable=False`: it never appears in orchestrator
routing and is only ever invoked from `seed`.

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
