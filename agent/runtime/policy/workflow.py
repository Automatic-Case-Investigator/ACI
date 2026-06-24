"""Workflow automation: deduplication, escalation policy, and audit events.

These are the platform-side policies that wrap an automatic run, independent of
the agent graph itself:

- **Deduplication** stops a flood of identical triggers (same case/alert cluster)
  from spawning redundant investigations.
- **Escalation** turns a completed run's verdict into a routing decision: auto-close
  a false positive, auto-escalate a true positive, hold an inconclusive for an
  analyst.
- **Audit events** (`triggered`, `deduped`, `escalated`, `diagnosed`, `posted`,
  `failed`) give the workflow a legible lifecycle in the event stream.

The escalation handler records the *decision* (and emits the audit event); the
actual connector side effect (TheHive comment, Slack message) is applied by the
caller that owns the connector tools.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...models import AgentRun
from ..infra.logbus import emit

# Workflow lifecycle audit-event kinds (AgentEvent.kind is a free CharField).
AUDIT_TRIGGERED = "triggered"
AUDIT_DEDUPED = "deduped"
AUDIT_DIAGNOSED = "diagnosed"
AUDIT_ESCALATED = "escalated"
AUDIT_POSTED = "posted"
AUDIT_FAILED = "failed"

# Active states for dedup purposes — a run in any of these is "already working".
_ACTIVE_STATES = (AgentRun.STATUS_QUEUED, AgentRun.STATUS_RUNNING)

# Verdict → escalation action.
ACTION_AUTO_CLOSE = "auto_close"
ACTION_AUTO_ESCALATE = "auto_escalate"
ACTION_HOLD = "hold"
ACTION_NONE = "none"


def find_duplicate_run(case_id: str, agent_name: str, window_seconds: int):
    """Return an active run for the same case+agent within the window, or None."""
    if window_seconds <= 0:
        return None
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    return (
        AgentRun.objects.filter(
            case_id=case_id,
            agent_name=agent_name,
            status__in=_ACTIVE_STATES,
            created_at__gte=since,
        )
        .order_by("-created_at")
        .first()
    )


def escalation_action(verdict) -> str:
    """Map a verdict contract (or None) to an escalation action.

    Reads the analyst-editable escalation map (settings UI) over the code defaults.
    """
    if not isinstance(verdict, dict):
        return ACTION_NONE
    from ..config.overrides import resolve_escalation_map

    return resolve_escalation_map().get(verdict.get("verdict"), ACTION_NONE)


def apply_escalation_policy(run: AgentRun, *, save: bool = True) -> dict:
    """Decide the escalation action for a completed run and record it.

    Records `{action, verdict, confidence}` under `run.metadata["escalation"]` and
    emits a `diagnosed` audit event plus an `escalated`/`posted`/`note` event for
    the chosen action. Returns the escalation dict. The actual connector side
    effect is left to the caller that holds the connector tools.
    """
    verdict = run.verdict if isinstance(run.verdict, dict) else None
    action = escalation_action(verdict)
    decision = {
        "action": action,
        "verdict": (verdict or {}).get("verdict"),
        "confidence": (verdict or {}).get("confidence"),
    }

    if save:
        meta = dict(run.metadata or {})
        meta["escalation"] = decision
        run.metadata = meta
        run.save(update_fields=["metadata", "updated_at"])

    src = "workflow"
    emit(src, AUDIT_DIAGNOSED,
         f"case {run.case_id}: verdict {decision['verdict'] or 'none'} "
         f"({decision['confidence'] or '?'})")
    if action == ACTION_AUTO_ESCALATE:
        emit(src, AUDIT_ESCALATED, f"case {run.case_id}: auto-escalated (tp)")
    elif action == ACTION_AUTO_CLOSE:
        emit(src, AUDIT_POSTED, f"case {run.case_id}: auto-closed (fp)")
    elif action == ACTION_HOLD:
        emit(src, "note", f"case {run.case_id}: held for analyst ({decision['verdict']})")

    return decision
