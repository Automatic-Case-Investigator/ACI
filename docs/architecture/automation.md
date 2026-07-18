# Workflows And Webhooks

Automatic workflows let an external event (a new SOAR case, a new SIEM alert) start an
agent run without an analyst typing a question — and, once that run completes, optionally
act on its verdict. The whole path is globally disabled by default and gated at three
independent levels, so enabling it is a deliberate, layered decision rather than a single
switch.

## Event -> Binding -> Run

The seam is intentionally small:

```text
Trigger (event_type, case_id, payload)
    -> WorkflowBinding (event_type -> agent_name, question builder)
    -> dispatch_run(agent_name, case_id, question, trigger=AUTO, dedupe_window=...)
```

- `Trigger` (`agent/runtime/triggers/base.py`) is the normalized event: `event_type`,
  `case_id`, and the raw `payload`.
- `WorkflowBinding` (same module) maps one `event_type` to an `agent_name` and a
  `build_question(trigger) -> str` callable that turns the event into the run's objective.
  Bindings self-register in `agent/runtime/triggers/bindings.py` and are looked up through
  `agent/runtime/triggers/registry.py` (`register` / `get_binding` / `list_bindings`).
- Two bindings ship today, both routing to `triage`:

  | Event | Agent | Question |
  |---|---|---|
  | `new_case` | `triage` | "A new case (...) was created. Triage it: read the case and linked alerts, diagnose the incident, and produce a prioritized investigation plan." |
  | `new_alert` | `triage` | "A new alert (...) was received. Triage it: inspect the alert, correlate related evidence, and decide whether it needs investigation." |

- `dispatch_trigger` (`agent/runtime/triggers/base.py`) is the single automatic entry
  point a webhook or poller calls. It resolves the binding, checks the global kill switch
  and the per-event override (see below), then calls `runtime.engine.dispatch.dispatch_run`
  — the same transport-agnostic dispatcher the orchestrator uses for interactive sub-agent
  calls (see [Runtime & Agent Graph](/documents/architecture/runtime/agent-graph#runtime-entry)). Automatic runs
  are simply `dispatch_run(..., trigger=AgentRun.TRIGGER_AUTO, dedupe_window=...)`.

## Trigger Providers (Payload Parsing)

A trigger source (TheHive, Wazuh) is registered independently of the MCP connector for
that same platform (`agent/runtime/triggers/providers.py`) — a system can receive webhook
events from a platform even if its MCP connector is disabled, since ingesting an event and
querying that platform for evidence are different concerns.

| Provider key | Events | `parse_payload` extracts |
|---|---|---|
| `thehive` (aliased from `aci-thehive`) | `new_case`, `new_alert` | `object`/`details`._id (or `rootId`/`case_id`), validated against `objectType` matching the event and `operation` being a creation/update |
| `wazuh` (aliased from `aci-wazuh`) | `new_alert` | `case_id`/`alert_id`/`id`/`rule.id`, falling back to `agent.id` |

`normalize_provider_key` maps the MCP provider keys (`aci-thehive`, `aci-wazuh`) onto the
trigger-provider keys (`thehive`, `wazuh`), so a `WorkflowTriggerConfig.provider_key` saved
either way resolves correctly. `parse_trigger_payload` returns `(case_id, None)` on success
or `(None, reason)` on a rejected/unparseable payload — the webhook view turns a rejection
into a `{"ignored": true, "reason": ...}` 200 response rather than an error, since an
unrecognized payload shape is an expected, non-exceptional occurrence (e.g. a platform
sending an event type nobody registered a binding for).

## Webhook Ingress

Two REST endpoints (`agent/views/webhooks.py`) ingest events, both requiring no
authentication (`PublicAPIView`) since the secret check happens per-trigger:

- **`POST /api/agent/webhooks/<trigger_id>/`** (`ConfiguredWebhookView`) — the general
  path. Looks up the analyst-configured `WorkflowTriggerConfig` by its stable slug id.
- **`POST /api/agent/webhooks/thehive/`** (`TheHiveWebhookView`) — a compatibility
  endpoint for TheHive's own webhook config UI, which posts to one fixed URL. It infers
  `new_case`/`new_alert` from the payload's `objectType` and resolves the matching enabled
  TheHive trigger by event type, then reuses the same handling as the generic path.

A configured webhook is accepted only when **all** of the following hold, checked in this
order (`_handle_configured_webhook`):

1. the `WorkflowTriggerConfig` row is `enabled`;
2. if the trigger has a `secret` set, the request supplies the same value via the
   `X-ACI-Webhook-Secret` header or a `?secret=` query parameter;
3. `RuntimeConfig.workflows_enabled` (or `WORKFLOWS_ENABLED` env fallback) is true — the
   global kill switch;
4. a `WorkflowBinding` is registered for the trigger's `event_type`;
5. the binding is enabled after applying any `WorkflowConfig` override
   (`resolve_workflow`, DB row wins over the binding's code default);
6. the trigger provider can parse a `case_id` out of the payload.

On success the view spawns a **daemon thread** that runs `asyncio.run(dispatch_trigger(...))`
and immediately returns `202 Accepted` with the resolved `trigger_id`/`event_type`/`case_id`
— the webhook call does not block on the agent run, which can take minutes. Any exception
inside that thread is logged (`log.exception`) rather than surfaced to the caller, since the
HTTP response has already been sent.

## Deduplication

`dispatch_run`'s `dedupe_window` (seconds) protects against a burst of identical events
(e.g. a platform retrying a webhook, or a case updated twice in quick succession) fanning
out into duplicate runs. When `dedupe_window > 0`, `find_duplicate_run(case_id, agent_name,
window_seconds)` (`agent/runtime/policy/workflow.py`) looks for an `AgentRun` with the same
`case_id` + `agent_name`, in an active status, created within the window; if one exists it
is returned as-is (with a `deduped` audit event) instead of starting a new run. `0` disables
deduplication entirely. The effective window is the per-trigger `WorkflowTriggerConfig.
dedupe_window` when the request came through a configured webhook, otherwise the binding's
code default as resolved by `resolve_workflow`.

## Escalation Policy

Once an automatic run **completes**, its verdict can drive an automatic SOAR action —
without an analyst having to open the case. This is two separate steps, both idempotent and
both run for every completed automatic run (not only ones an operator explicitly enabled),
so the decision is always visible in `run.metadata` even when no side effect fires:

1. **`apply_escalation_policy(run)`** (`agent/runtime/policy/workflow.py`) reads the run's
   verdict and looks up `resolve_escalation_map()[verdict]` — the analyst-editable
   `EscalationRule` table overriding a code default map — to get one of:

   | Action | Meaning |
   |---|---|
   | `auto_close` | Case is closed as a false positive. |
   | `auto_escalate` | Case is flagged for immediate analyst review. |
   | `hold` | Verdict is posted as a note; no state change. |
   | `none` | No action recorded. |

   The decision (`action`, `verdict`, `confidence`) is written to
   `run.metadata["escalation"]` and a `diagnosed` audit event is emitted, plus
   `escalated`/`posted` depending on the action — regardless of whether the side effect
   below actually executes.

2. **`execute_escalation(run)`** (`agent/runtime/policy/escalation.py`) performs the actual
   TheHive call for the recorded decision, but only for **automatic** runs
   (`trigger != AgentRun.TRIGGER_INTERACTIVE`) — an interactive analyst session lets the
   analyst decide whether to act, rather than the platform acting on their behalf.
   - `auto_close` → `update_case(status="FalsePositive")` + a comment.
   - `auto_escalate` → a comment flagging immediate review required.
   - `hold` → a comment stating the verdict, held for analyst review.
   - A run whose `source_entity_type` is `alert` (no linked case id) skips the TheHive
     call entirely — there is nothing to update — and only logs a note.
   - **Idempotent**: `run.metadata["escalation"]["executed_at"]` is checked first, so
     resuming a run that already executed its escalation does not double-post. Any
     exception is caught, recorded as `execution_error`, and audited as `failed` rather
     than raised — a broken TheHive connection must not fail the run itself.
   - The client is built the same way the SOAR MCP connector is: through
     `resolve_settings("aci-thehive", ...)`, so it uses whichever connection is marked
     **active** in Settings → Integrations (see
     [MCP And Tool Policy](/documents/architecture/tools#integration-connections-many-per-provider-one-active)).

## Configuration Precedence

Every automation knob is DB-over-code, resolved the same way as the rest of the settings
system:

- **Global kill switch** — `RuntimeConfig.workflows_enabled` (DB) over `WORKFLOWS_ENABLED`
  (`.env`); `false`/unset means automatic workflows never fire, regardless of any trigger
  or binding configuration.
- **Per-binding enable/dedupe** — `WorkflowConfig` (keyed by `event_type`) overrides the
  `WorkflowBinding`'s code-defined `enabled`/`dedupe_window` (`resolve_workflow`).
- **Per-trigger enable/secret/dedupe** — `WorkflowTriggerConfig` (keyed by a stable slug
  id, one row per configured webhook URL) carries its own `enabled`, optional `secret`, and
  `dedupe_window`, editable in Settings → Automation.
- **Escalation actions** — `EscalationRule` (keyed by verdict) overrides the code-default
  verdict → action map (`resolve_escalation_map`).

## Manual / Headless Firing

Outside of a webhook, a binding can be fired directly for testing or a future scheduler:

```bash
python manage.py run_workflow new_case ~247152824
python manage.py run_workflow new_alert ~247152824 --payload '{"key": "value"}'
```

This calls `agent.runtime.triggers.fire(trigger)` — a synchronous sibling of
`dispatch_trigger` with the same `workflows_enabled()` gate and `WorkflowBinding` lookup,
kept intentionally simpler for a one-off CLI invocation: it checks the binding's own
`enabled` flag but does **not** apply the `WorkflowConfig` DB override or any dedup window
(`dispatch_run` is called with the default `dedupe_window=0`). It exists to prove the
`Trigger -> WorkflowBinding -> dispatch_run` seam headlessly; a real scheduler that needs
the DB overrides and dedup should call `dispatch_trigger` directly instead.
