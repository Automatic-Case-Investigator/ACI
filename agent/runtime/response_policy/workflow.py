"""Workflow automation: deduplication, response policy, and audit events.

These are the platform-side policies that wrap an automatic run, independent of
the agent graph itself:

- **Deduplication** stops a flood of identical triggers (same case/alert cluster)
  from spawning redundant investigations.
- **Response policy** turns a run's outcome into a routing decision by looking up
  the `(verdict, subject)` cell in `policy` — or the failure row, when the run
  produced no usable verdict at all.
- **Audit events** (`triggered`, `deduped`, `diagnosed`, `investigated`, `posted`,
  `failed`) give the workflow a legible lifecycle in the event stream.

The handler records the *decision* (and emits the audit event); the actual connector
side effect is applied by `execution`, which owns the connector tools. That split is
what keeps the decision auditable independently of whether its side effect succeeded.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...models import AgentRun
from ..infra.logbus import emit

# Workflow lifecycle audit-event kinds (AgentEvent.kind is a free CharField).
AUDIT_TRIGGERED = "triggered"
AUDIT_DEDUPED = "deduped"
AUDIT_DIAGNOSED = "diagnosed"
AUDIT_INVESTIGATED = "investigated"
AUDIT_POSTED = "posted"
AUDIT_FAILED = "failed"

# Where the response decision lives in `run.metadata`. Runs recorded before the
# `escalate` action was removed stored it under `escalation`; reads fall back to
# that key so historical run pages keep rendering, while writes only ever use the
# current one (and drop the legacy copy) so the two cannot drift apart.
DECISION_KEY = "response"
_LEGACY_DECISION_KEY = "escalation"


def read_decision(run) -> dict:
    """The response decision recorded on a run, preferring the current key."""
    meta = getattr(run, "metadata", None) or {}
    for key in (DECISION_KEY, _LEGACY_DECISION_KEY):
        value = meta.get(key)
        if isinstance(value, dict) and value:
            return value
    return {}


def store_decision(meta: dict, decision: dict) -> dict:
    """Write `decision` into a metadata dict under the current key.

    Returns the same dict for chaining. Removes any legacy copy so a run touched
    after the rename does not carry two decisions that can disagree.
    """
    meta[DECISION_KEY] = decision
    meta.pop(_LEGACY_DECISION_KEY, None)
    return meta


# Active states for dedup purposes — a run in any of these is "already working".
_ACTIVE_STATES = (AgentRun.STATUS_QUEUED, AgentRun.STATUS_RUNNING)

# The response-action vocabulary lives in `policy` (and `models.ResponsePolicy`).
# Only the null action is re-exported here, because the decision path needs a value
# to fall back to before any policy lookup happens.
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


def response_action(verdict, run=None) -> str:
    """Map a verdict contract (or None) to a configured response action.

    Reads the analyst-editable response matrix (settings UI) over the code defaults.
    Without a `run` the subject cannot be determined, so the case row is assumed —
    that is the only subject whose actions are executable today.
    """
    if not isinstance(verdict, dict):
        return ACTION_NONE
    from ..config.overrides import resolve_response_policy
    from . import policy

    subject = policy.subject_for_run(run) if run is not None else policy.CASE
    return resolve_response_policy().get((verdict.get("verdict"), subject), ACTION_NONE)


def _failure_reason(run: AgentRun, verdict: dict | None) -> str:
    """Why this run has no usable verdict, or '' when it produced one.

    An over-budget run is NOT a failure here: it finished and produced a verdict,
    just a truncated one, so the verdict rows apply. The verdict pipeline has
    already floored the weak cases (`apply_open_gaps_policy` demotes a tp/fp with
    blocking gaps; `apply_completeness_floor` floors an over-budget fp).
    """
    if getattr(run, "status", "") == AgentRun.STATUS_FAILED:
        return "run_failed"
    if not verdict or not verdict.get("verdict"):
        return "no_verdict"
    return ""


def apply_response_policy(run: AgentRun, *, save: bool = True) -> dict:
    """Decide the response action for a completed run and record it.

    Records the decision under `run.metadata[DECISION_KEY]` and emits a `diagnosed`
    audit event plus a `posted`/`note` event for the chosen action. Returns the
    decision dict. The actual connector side effect is left to `execution.py`.
    """
    from ..config.overrides import resolve_response_policy
    from . import policy

    verdict = run.verdict if isinstance(run.verdict, dict) else None
    subject = policy.subject_for_run(run)
    failure = _failure_reason(run, verdict)

    if failure:
        # No usable verdict, so there is no verdict row to consult. Without this the
        # run would leave no trace at all — the worst outcome for an unattended
        # workflow, because absent coverage is indistinguishable from clean coverage.
        action = resolve_response_policy().get(
            (policy.FAILURE_FALLBACK, subject),
            policy.default_action(policy.FAILURE_FALLBACK, subject),
        )
    else:
        action = response_action(verdict, run)

    decision = {
        "action": action,
        "subject": subject,
        "verdict": (verdict or {}).get("verdict"),
        "confidence": (verdict or {}).get("confidence"),
    }
    if failure:
        decision["fallback_reason"] = failure

    if save:
        meta = store_decision(dict(run.metadata or {}), decision)
        run.metadata = meta
        run.save(update_fields=["metadata", "updated_at"])

    src = "workflow"
    if failure:
        emit(
            src,
            AUDIT_DIAGNOSED,
            f"{subject} {run.case_id}: no usable verdict ({failure}) → "
            f"failure fallback: {action}",
        )
    else:
        emit(
            src,
            AUDIT_DIAGNOSED,
            f"{subject} {run.case_id}: verdict {decision['verdict'] or 'none'} "
            f"({decision['confidence'] or '?'}) → {action}",
        )
    if action == policy.RESOLVE:
        emit(src, AUDIT_POSTED, f"case {run.case_id}: resolved ({decision['verdict']})")

    return decision
