"""Execute the response decision recorded by apply_response_policy.

apply_response_policy (workflow.py) records the routing decision on the run and
emits audit events, but explicitly delegates the side effect to the caller. This
module is that caller: it reads the recorded decision and performs the
corresponding operation — posting the agent's report as a TheHive case page,
updating case status, promoting an alert, or dispatching a follow-up investigation run.

Called from dispatch.py for automatic (non-interactive) runs only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ...models import AgentRun
from ..infra.logbus import emit
from . import policy
from .workflow import (
    AUDIT_FAILED,
    AUDIT_INVESTIGATED,
    AUDIT_POSTED,
    read_decision,
    store_decision,
)


def execute_response(run: AgentRun) -> None:
    """Execute the side effect for a completed run's response decision.

    Idempotent: a run that already has an `executed_at` timestamp in its recorded
    decision is skipped, so resuming a failed run does not double-post.
    """
    decision = read_decision(run)
    action = decision.get("action")
    if not action or action == policy.NONE:
        return
    if decision.get("executed_at"):
        return

    # `investigate` is the one action that is not a SOAR write — it spends compute
    # instead, and works for every subject including a standalone alert.
    if action == policy.INVESTIGATE:
        _launch_investigation(run)
        return

    # `promote_case` is the one write that TARGETS an alert, so it must be reached
    # before the guard below that skips alert-subject runs for lack of a case id —
    # creating that case is the whole point of the action.
    if (
        action != policy.PROMOTE_CASE
        and (run.metadata or {}).get("source_entity_type") == "alert"
    ):
        emit(
            "workflow",
            "note",
            f"alert {run.case_id}: response decision recorded; no case side-effect without linked case id",
        )
        _mark_executed(run, skipped_reason="standalone_alert_no_case")
        return

    from aci_thehive.client import TheHiveClient
    from ..config import resolve_settings
    from ..providers.registry import get_provider

    try:
        _provider = get_provider("aci-thehive")
        _resolved = resolve_settings(
            "aci-thehive", _provider.setting_defaults() if _provider else {}
        )
        client = TheHiveClient(
            base_url=_resolved.get("base_url") or "",
            host=_resolved.get("host") or "",
            port=_resolved.get("port") or "9000",
            api_key=_resolved.get("api_key") or "",
            verify_tls=_resolved.get("verify_tls") or "true",
        )
        verdict_label = (decision.get("verdict") or "unknown").upper()
        confidence = decision.get("confidence") or "?"

        if action == policy.RESOLVE:
            status = "FalsePositive" if decision.get("verdict") == "fp" else "Resolved"
            # Report first, then the status change: if the update fails, the case is
            # still left with the reasoning rather than a bare unexplained close.
            client.post_report(
                run.case_id,
                _report_body(run, verdict_label, confidence, decision),
                title=_report_title(run, verdict_label, decision),
            )
            client.update_case(run.case_id, {"status": status})
            emit(
                "workflow",
                AUDIT_POSTED,
                f"case {run.case_id}: resolved as {status} in TheHive",
            )

        elif action == policy.DOCUMENT:
            client.post_report(
                run.case_id,
                _report_body(run, verdict_label, confidence, decision),
                title=_report_title(run, verdict_label, decision),
            )
            emit(
                "workflow",
                AUDIT_POSTED,
                f"case {run.case_id}: investigation report posted",
            )

        elif action == policy.PROMOTE_CASE:
            # Promote first so the case exists, then document onto it. TheHive copies
            # the alert's title, severity, tags and observables across, so the case
            # already carries the alert's context — the report adds the reasoning.
            created = client.promote_alert_to_case(run.case_id) or {}
            new_case_id = str(
                created.get("_id") or created.get("id") or created.get("caseId") or ""
            ).strip()
            if not new_case_id:
                raise ValueError(
                    f"promotion of alert {run.case_id} returned no case id: {created!r}"
                )
            client.post_report(
                new_case_id,
                _report_body(run, verdict_label, confidence, decision),
                title=_report_title(run, verdict_label, decision),
            )
            emit(
                "workflow",
                AUDIT_POSTED,
                f"alert {run.case_id}: promoted to case {new_case_id} and documented",
            )
            _mark_executed(run, promoted_case_id=new_case_id)
            return

        _mark_executed(run)

    except Exception as exc:
        emit(
            "workflow",
            AUDIT_FAILED,
            f"case {run.case_id}: response execution failed: {exc}",
        )
        _mark_error(run, str(exc))


_FALLBACK_EXPLANATION = {
    "run_failed": "the run did not complete — it stopped with an error",
    "no_verdict": "the run finished but produced no usable verdict",
}


def _report_title(run: AgentRun, verdict_label: str, decision: dict) -> str:
    if decision.get("fallback_reason"):
        return f"ACI {run.agent_name} did not complete"
    return f"ACI {verdict_label} — {run.agent_name} report"


def _report_body(
    run: AgentRun, verdict_label: str, confidence: str, decision: dict | None = None
) -> str:
    """The agent's report, headed by the verdict that drove the response.

    `run.result` already ends with the fenced verdict JSON block, so the header is
    the human-readable summary of it rather than a duplicate — an analyst opening
    the case page sees the disposition before the narrative.

    When the response came from the failure fallback there is no verdict to state,
    so the header says what went wrong instead. Being explicit matters here: a case
    that silently received nothing looks exactly like one that was triaged clean.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    fallback = (decision or {}).get("fallback_reason")
    if fallback:
        header = (
            f"**ACI {run.agent_name} did not produce a verdict** — "
            f"{_FALLBACK_EXPLANATION.get(fallback, fallback)}.  \n"
            f"*Run `{str(run.id)[:8]}` — {stamp}*\n\n"
            "This case has NOT been triaged. Anything below is partial.\n\n---\n\n"
        )
    else:
        header = (
            f"**ACI {run.agent_name} verdict: {verdict_label}** (confidence: {confidence})  \n"
            f"*Run `{str(run.id)[:8]}` — {stamp}*\n\n---\n\n"
        )
    body = (run.result or "").strip()
    if not body:
        body = "_The run produced no report body._"
    return header + body


def _launch_investigation(run: AgentRun) -> None:
    """Dispatch a follow-up investigation run for a verdict that asked for one.

    Marked executed BEFORE dispatching: the child run can outlive this call, and the
    idempotency guard must already be in place so a retry cannot double-launch.
    """
    if run.agent_name == "investigation":
        emit(
            "workflow",
            "note",
            f"{run.case_id}: investigation already ran; not re-launching",
        )
        _mark_executed(run, skipped_reason="already_investigation")
        return

    _mark_executed(run)
    try:
        import asyncio

        from ..engine.dispatch import dispatch_run

        meta = dict(run.metadata or {})
        asyncio.run(
            dispatch_run(
                "investigation",
                run.case_id,
                f"Investigate {run.case_id} — triage returned "
                f"{(run.verdict or {}).get('verdict', 'needs_investigation')}.",
                trigger=AgentRun.TRIGGER_AUTO,
                metadata={
                    "source_entity_id": meta.get("source_entity_id") or run.case_id,
                    "source_entity_type": meta.get("source_entity_type") or "case",
                    "trigger_provider": meta.get("trigger_provider", ""),
                    "parent_run_id": str(run.id),
                },
            )
        )
        emit(
            "workflow",
            AUDIT_INVESTIGATED,
            f"{run.case_id}: investigation dispatched by response policy",
        )
    except Exception as exc:
        emit(
            "workflow",
            AUDIT_FAILED,
            f"{run.case_id}: investigation dispatch failed: {exc}",
        )
        _mark_error(run, str(exc))


def _mark_executed(
    run: AgentRun,
    *,
    skipped_reason: str | None = None,
    promoted_case_id: str | None = None,
) -> None:
    meta = dict(run.metadata or {})
    decision = {**read_decision(run)}
    decision.pop("execution_error", None)
    decision["executed_at"] = datetime.now(timezone.utc).isoformat()
    if skipped_reason:
        decision["side_effect_skipped"] = skipped_reason
    if promoted_case_id:
        # Recorded so the run history can link to the case the alert became.
        decision["promoted_case_id"] = promoted_case_id
    AgentRun.objects.filter(id=run.id).update(metadata=store_decision(meta, decision))


def _mark_error(run: AgentRun, error: str) -> None:
    meta = dict(run.metadata or {})
    decision = {**read_decision(run), "execution_error": error}
    AgentRun.objects.filter(id=run.id).update(metadata=store_decision(meta, decision))
