"""Execute the escalation decision recorded by apply_escalation_policy.

apply_escalation_policy (workflow.py) records the routing decision in
run.metadata["escalation"] and emits audit events, but explicitly delegates
the TheHive side-effect to the caller. This module is that caller: it reads
the recorded decision and performs the corresponding TheHive operation
(case status update and/or workflow note page).

Called from dispatch.py for automatic (non-interactive) runs only.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ...models import AgentRun
from ..infra.logbus import emit
from .workflow import (
    ACTION_AUTO_CLOSE,
    ACTION_AUTO_ESCALATE,
    ACTION_HOLD,
    AUDIT_ESCALATED,
    AUDIT_FAILED,
    AUDIT_POSTED,
)


def execute_escalation(run: AgentRun) -> None:
    """Execute the TheHive side-effect for a completed run's escalation decision.

    Idempotent: a run that already has an `executed_at` timestamp in its
    escalation metadata is skipped, so resuming a failed run does not
    double-post.
    """
    decision = (run.metadata or {}).get("escalation", {})
    action = decision.get("action")
    if not action or action == "none":
        return
    if decision.get("executed_at"):
        return
    if (run.metadata or {}).get("source_entity_type") == "alert":
        emit(
            "workflow",
            "note",
            f"alert {run.case_id}: escalation decision recorded; no case side-effect without linked case id",
        )
        _mark_executed(run, skipped_reason="standalone_alert_no_case")
        return

    from aci_thehive.client import TheHiveClient
    from ..config import resolve_settings
    from ..providers.registry import get_provider

    try:
        _provider = get_provider("aci-thehive")
        _resolved = resolve_settings("aci-thehive", _provider.setting_defaults() if _provider else {})
        client = TheHiveClient(
            host=_resolved.get("host") or None,
            port=_resolved.get("port") or None,
            api_key=_resolved.get("api_key") or None,
            verify_tls=_resolved.get("verify_tls") or None,
        )
        verdict_label = (decision.get("verdict") or "unknown").upper()
        confidence = decision.get("confidence") or "?"

        if action == ACTION_AUTO_CLOSE:
            client.update_case(run.case_id, {"status": "FalsePositive"})
            client.post_case_comment(
                run.case_id,
                f"ACI auto-closed as FALSE POSITIVE (confidence: {confidence}). "
                "Review the investigation report for details.",
            )
            emit("workflow", AUDIT_POSTED, f"case {run.case_id}: auto-closed FP in TheHive")

        elif action == ACTION_AUTO_ESCALATE:
            client.post_case_comment(
                run.case_id,
                f"ACI escalated as TRUE POSITIVE (confidence: {confidence}). "
                "Immediate analyst review required. See investigation report.",
            )
            emit("workflow", AUDIT_ESCALATED, f"case {run.case_id}: auto-escalated TP in TheHive")

        elif action == ACTION_HOLD:
            client.post_case_comment(
                run.case_id,
                f"ACI verdict: {verdict_label} (confidence: {confidence}) — held for analyst review.",
            )
            emit("workflow", "note", f"case {run.case_id}: hold note posted")

        _mark_executed(run)

    except Exception as exc:
        emit("workflow", AUDIT_FAILED, f"case {run.case_id}: escalation execution failed: {exc}")
        _mark_error(run, str(exc))


def _mark_executed(run: AgentRun, *, skipped_reason: str | None = None) -> None:
    meta = dict(run.metadata or {})
    escalation = {**meta.get("escalation", {})}
    escalation.pop("execution_error", None)
    escalation["executed_at"] = datetime.now(timezone.utc).isoformat()
    if skipped_reason:
        escalation["side_effect_skipped"] = skipped_reason
    meta["escalation"] = escalation
    AgentRun.objects.filter(id=run.id).update(metadata=meta)


def _mark_error(run: AgentRun, error: str) -> None:
    meta = dict(run.metadata or {})
    meta["escalation"] = {**meta.get("escalation", {}), "execution_error": error}
    AgentRun.objects.filter(id=run.id).update(metadata=meta)
