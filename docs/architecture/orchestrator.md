# Orchestrator

## Public Reasoning Before Tools

This mechanism lives in `agent/runtime/analysis/intent.py`
(`generate_public_intent`) and is consumed only by the orchestrator's own
turn loop (`agent/runtime/orchestrator/driver.py`) — **not** by the `triage`
or `investigation` LangGraph nodes, which call the tool-bound model directly
from `think` with no separate pre-tool intent phase.

Each orchestrator turn that may call a tool is two-phase:

1. `generate_public_intent` calls an unbound text model and requests a
   state-grounded public progress summary.
2. Each provider delta is emitted as transient `intent_delta`.
3. The accumulated statement is persisted as a durable `intent` event.
4. The orchestrator calls the tool-bound model and, if it requests tools,
   emits `call` and then invokes them.

The event ordering contract is:

```text
intent_delta... -> intent -> call -> result
```

This sequence applies when the intent model returns text. With an empty or failed
intent request, execution continues as `call -> result` with no replacement event.

The streamed narrative is free-form Markdown. It explains relevant established
state, the current interpretation, uncertainty or blockers, and the intended next
action. It may use short paragraphs, bullets, emphasis, inline code, or brief
headings, but follows no fixed schema.

This provides the operational information normally sought from visible
"thinking aloud" without exposing private chain-of-thought. Prompts prohibit
token-level reasoning, exhaustive step-by-step internal deliberation, predicted
results, and unsupported claims. The next action may invoke a capability,
produce output, request information, wait, stop, or otherwise advance or
conclude the objective. If generation is empty, unsupported, or fails, no
synthetic intent is emitted and execution continues to the action model.

Cancellation is checked after intent generation and before execution. An analyst
can therefore stop a run after seeing its intended action without allowing the
announced tool to run.

The dashboard maintains separate stream state for final orchestrator answers and
public reasoning narratives. Markdown is rendered as deltas arrive in real
time and is also rendered from the durable event after reload. Completed
narratives are durable; partial deltas are intentionally not replayed.

Guaranteed intent adds one text-only model request per orchestrator
tool-capable turn. This increases latency and model usage in exchange for
strict visibility before side effects.

## Orchestrator And Session Publication

The orchestrator is a separate package runtime under
`agent/runtime/orchestrator/` with dedicated `messages`, `session`, `tools`,
`prompts`, and `driver` modules. It is responsible for analyst conversation
state, specialist routing, and durable analyst-visible transcript updates.

Specialist completion is normalized through one publication path:

- orchestrator-triggered specialist completion updates the shared
  `OrchestratorSession`;
- direct resume and restart paths republish through
  `agent.dashboard.runner.session_state.publish_specialist_result_to_session`;
- shared session mutation logic lives in
  `agent.runtime.orchestrator.specialist_sync`.

This keeps analyst-visible session state, verdict propagation, and resumed
specialist reports aligned regardless of whether the specialist finished through
the orchestrator tool loop or a direct continuation endpoint.
