"""The `assess` node: produces a completed task's report and its findings verdicts.

It does NOT decide whether the task is done — `interpret` owns that. This node
synthesises or repairs the three-section report, classifies each `## Findings`
bullet for the pivot node's board gating, and completes the task.
"""
from __future__ import annotations

from ...infra.logbus import emit, src_label
from ..findings_model import build_evidence_digest, verify_findings_model
from ..interpretation import _DEFAULT_STOP_CONDITION
from ..nodes_loop import _MAX_TASK_TOOL_CALLS
from ..parsing import _missing_summary_sections, _missing_triage_sections
from ..reflection import review_task_model
from ..sanitize import _sanitize_history, _sanitize_message
from ..state import AgentState
from ..synthesis import _execution_record
from ..timeutil import _find_timestamp_range
from ..toolio import _SEED_TASK_TITLE, _call, _emit_node_entry, _is_error_tool_result, _tmap, _track_input_tokens
from ..validation import _board_compromise_facts, _unpivoted_network_iocs
from datetime import datetime, timedelta
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
import json
import re
import logging

from ..coverage import (
    _count_evidence_queries, _last_search_hit_count,
    _unqueried_post_peak_clusters, _unqueried_time_ranges,
)
from ._shared import _finding_bullet, _findings_section_text, _merge_preserved_findings, _new_leads_section_text, _preserved_findings_from_state

log = logging.getLogger(__name__)


async def _force_report_sections(
    state: AgentState, config, src, new_ctx: int, missing: list[str],
) -> tuple[str, int]:
    """Last-resort structured rewrite when synthesis still left sections missing.

    Repairs the report in place instead of routing the task back to `think`: the
    completion decision belongs to `interpret` and has already been made, so a
    missing heading must not re-open it.
    """
    model = config["configurable"].get("model")
    if not model:
        return "", new_ctx
    sys_prompt = config["configurable"].get("system_prompt", "")
    try:
        text_only = model.bind_tools([])
        prompt = HumanMessage(content=(
            f"Your report is missing or has an empty {', '.join(missing)} section. Your "
            "evidence is sufficient — do not make further tool calls. Write the FINAL "
            "report now using the mandatory three-section format:\n\n"
            "## Findings\n## Hypotheses\n## New Leads\n\n"
            "Populate every section from the tool results above; put each confirmed "
            "indicator (reverse shell, C2/callback, command execution) under ## Findings "
            "as a bullet with its event ID. Use '- None.' only for a genuinely empty section."
        ))
        resp = await text_only.ainvoke(
            [SystemMessage(content=sys_prompt)] + _sanitize_history(state["messages"] + [prompt])
        )
        _sanitize_message(resp)
        return (resp.content or "").strip(), _track_input_tokens(resp, src, new_ctx)
    except Exception as exc:  # noqa: BLE001 - never fail the task on the repair path
        log.warning("[%s] report section repair failed: %s", state["agent_name"], exc)
        return "", new_ctx


async def _synthesize_investigation_report(state: AgentState, config, src, new_ctx: int) -> tuple[str, int]:
    """Write the final three-section per-task report from the gathered evidence.

    Used on conclude (after the evidence review passes) when the agent deferred or
    under-wrote its report — so the board and final report always have grounded
    findings/hypotheses/leads. One text-only model call; ('' , new_ctx) on failure.
    """
    model = config["configurable"].get("model")
    if not model:
        return "", new_ctx
    sys_prompt = config["configurable"].get("system_prompt", "")
    # Give the model the confirmed findings the interpret loop already distilled into the
    # ledger. Without them the synthesis re-derives findings from the raw (often compacted)
    # tool results and drops some — which `_merge_preserved_findings` then mechanically
    # appends, so a genuine finding survives but as a bare bolt-on that never grounded the
    # report's Hypotheses/New Leads. Handing the model its own confirmed state lets it write
    # them in as first-class findings AND reason forward from them, so the post-hoc merge
    # becomes a rare backstop instead of the routine path.
    confirmed_block = ""
    confirmed = _preserved_findings_from_state(state)
    if confirmed:
        confirmed_block = (
            "\n\nYou have ALREADY CONFIRMED the following finding(s) during this task — each is "
            "backed by retrieved evidence. Carry EVERY one into ## Findings with its event id "
            "(do not drop, weaken, or re-derive them), and let them ground your ## Hypotheses "
            "and ## New Leads:\n" + "\n".join(_finding_bullet(f) for f in confirmed)
        )
    instruction = (
        "Evidence gathering is complete and reviewed. Write your FINAL report now, grounded "
        "ONLY in the tool results above — do not make any further tool calls. Use exactly the "
        "mandatory three-section format:\n\n## Findings\n## Hypotheses\n## New Leads\n\n"
        "Each ## Findings bullet must be a NEW evidence-backed fact with its event ID. Use "
        "'- None.' for a genuinely empty section." + confirmed_block
    )
    try:
        text_only = model.bind_tools([])
        msgs = _sanitize_history(state["messages"] + [HumanMessage(content=instruction)])
        resp = await text_only.ainvoke([SystemMessage(content=sys_prompt)] + msgs)
        _sanitize_message(resp)
        return (resp.content or "").strip(), _track_input_tokens(resp, src, new_ctx)
    except Exception as exc:
        log.warning("[%s] task report synthesis failed: %s", state["agent_name"], exc)
        return "", new_ctx
async def assess(state: AgentState, config) -> dict:
    """Validate the latest task output and decide whether to retry, persist, or advance."""
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "assess", state)
    tools = config["configurable"]["tools"]
    complete_fn = _tmap(tools).get("complete_task")
    last = state["messages"][-1]
    task = state.get("current_task")
    new_ctx = state.get("ctx_tokens", 0)

    final_answer = (last.content or "").strip()
    if not final_answer:
        # Model returned empty — try a text-only synthesis call before falling back
        # to the mechanical execution record. This recovers the common case where a
        # small model makes tool calls correctly but produces no narrative reply.
        model = config["configurable"].get("model")
        sys_prompt = config["configurable"].get("system_prompt", "")
        has_tool_results = any(isinstance(m, ToolMessage) for m in state["messages"])
        if model and has_tool_results:
            emit(src, "note", "empty response — requesting text synthesis")
            text_only = model.bind_tools([])
            try:
                if state["agent_name"] == "triage":
                    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
                    synth_instruction = (
                        "Based on the tool results above, write your complete triage report "
                        "as text now. Do not make any further tool calls. In ## Investigation "
                        "Plan, every item must include an explicit absolute time window. If "
                        "an item does not have a narrower evidence-derived range, derive it "
                        f"from the configured default vicinity window of ±{vicinity_hours} "
                        "hours around the anchor timestamp. Do not use ±24 hours unless "
                        "this run's configured value is 24. If an item intentionally uses "
                        f"a narrower range, state why it is narrower than ±{vicinity_hours} "
                        "hours."
                    )
                else:
                    synth_instruction = (
                        "Based on the tool results above, write your complete analysis "
                        "and findings as text now. Do not make any further tool calls."
                    )
                synth_msgs = _sanitize_history(
                    state["messages"] + [HumanMessage(content=synth_instruction)]
                )
                synth_resp = await text_only.ainvoke([SystemMessage(content=sys_prompt)] + synth_msgs)
                _sanitize_message(synth_resp)
                final_answer = (synth_resp.content or "").strip()
                new_ctx = _track_input_tokens(synth_resp, src, new_ctx)
            except Exception as exc:
                log.warning("[%s] assess synthesis failed: %s", state["agent_name"], exc)
        if not final_answer:
            final_answer = _execution_record(state["messages"])

    preserved_findings = _preserved_findings_from_state(state)
    if preserved_findings:
        merged_answer = _merge_preserved_findings(final_answer, preserved_findings)
        if merged_answer != final_answer:
            emit(src, "note", "task review: restored confirmed finding(s) from task ledger")
            final_answer = merged_answer

    # --- Per-task findings review -------------------------------------------------------
    # This node PRODUCES the task's output; it does not judge whether the task is done
    # (that is `interpret`'s decision alone). The review runs to classify each ## Findings
    # bullet against the evidence actually retrieved, and those verdicts are stashed for
    # the pivot node's board gating. Fail-open: a model failure falls back to the regex
    # completeness check and the task still completes.
    findings_verification_state: dict | None = None
    reviewable = (
        task is not None
        and _SEED_TASK_TITLE not in (task.get("title") or "").lower()
    )

    if reviewable and state["agent_name"] == "investigation":
        # Review the EVIDENCE before the report is finalized (retrieve → verify → conclude).
        # The keep-working decision is made on what the task actually retrieved, so it can
        # interrupt BEFORE the agent commits findings/hypotheses/leads — instead of
        # critiquing a report it already wrote. On conclude the three-section report is
        # finalized (synthesized from the evidence if the agent deferred it), and only then
        # are its findings classified for the board.
        from ...analysis.query_memo import BROAD_HIT_THRESHOLD

        model = config["configurable"].get("model")
        evidence_queries = _count_evidence_queries(state["messages"])
        hit_count = _last_search_hit_count(state["messages"])
        digest, board_facts = build_evidence_digest(state, state["messages"])
        # Board compromise artifacts the agent has NOT surfaced in its ## Findings — the
        # decoded evidence is on its board but its report doesn't reflect it.
        _fa_lower = final_answer.lower()
        unreported = [bf for bf in _board_compromise_facts(state) if bf.lower() not in _fa_lower]
        # The completion contract the interpret loop derived for this task (skip the
        # generic default — only a real objective decomposition is a usable yardstick).
        ledger_stop = str((state.get("task_ledger") or {}).get("stop_condition") or "").strip()
        if ledger_stop == _DEFAULT_STOP_CONDITION:
            ledger_stop = ""
        review = await review_task_model(
            model,
            findings_section=_findings_section_text(final_answer),
            new_leads_section=_new_leads_section_text(final_answer),
            evidence_digest=digest,
            board_facts=board_facts,
            current_task=task,
            agent_name=state["agent_name"],
            signals={
                "evidence_queries": evidence_queries,
                "hit_count": hit_count,
                "hit_ceiling": hit_count is not None and hit_count >= BROAD_HIT_THRESHOLD,
                "unpivoted_iocs": _unpivoted_network_iocs(final_answer),
                "unqueried_clusters": _unqueried_post_peak_clusters(state["messages"]),
                "unqueried_time_ranges": _unqueried_time_ranges(state["messages"]),
                "unreported_compromise_artifacts": unreported,
            },
            stop_condition=ledger_stop,
        )
        # NOTE: `review.keep_working` is deliberately ignored. Completion is decided by
        # `interpret` alone; this node only produces the task's report and findings. The
        # review still runs because it also classifies each ## Findings bullet, which the
        # pivot node needs for board gating. The zero-evidence backstop it used to carry
        # now lives in `_route_interpret`, where the completion decision is made.
        # Conclude: finalize the three-section report now that the review has passed. If the
        # agent deferred or under-wrote it, synthesize it from the gathered evidence so the
        # board and final report always have grounded findings/hypotheses/leads.
        report_synthesized = False
        missing = _missing_summary_sections(final_answer)
        if missing:
            synthesized, new_ctx = await _synthesize_investigation_report(
                state, config, src, new_ctx
            )
            if synthesized:
                final_answer = synthesized
                if preserved_findings:
                    final_answer = _merge_preserved_findings(final_answer, preserved_findings)
                report_synthesized = True
                missing = _missing_summary_sections(final_answer)
            if missing:
                # Repair in place rather than routing back to `think`. The task IS done —
                # interpret decided that — so sending it back around the loop to fix a
                # heading would re-open a closed completion decision.
                emit(src, "note",
                     f"task review: report still missing section(s) {', '.join(missing)} — "
                     "forcing structured finalization")
                repaired, new_ctx = await _force_report_sections(
                    state, config, src, new_ctx, missing,
                )
                if repaired and len(_missing_summary_sections(repaired)) < len(missing):
                    final_answer = repaired
                    if preserved_findings:
                        final_answer = _merge_preserved_findings(final_answer, preserved_findings)
                    report_synthesized = True
                    missing = _missing_summary_sections(final_answer)

        # Board-quality gating: classify the FINALIZED report's findings. Reuse the review's
        # verdicts only when it judged this same report (the agent wrote it directly);
        # re-classify when we synthesized a fresh report it never saw. Fail-open → None
        # (the pivot node then records every real bullet).
        if not missing:
            if review is not None and not report_synthesized:
                findings_verification_state = review.findings_state()
            else:
                verification = await verify_findings_model(
                    model,
                    findings_section=_findings_section_text(final_answer),
                    evidence_digest=digest,
                    board_facts=board_facts,
                    current_task=task,
                    agent_name=state["agent_name"],
                )
                findings_verification_state = verification.to_state() if verification else None

    if complete_fn and task:
        await _call(complete_fn, {"task_id": task["id"], "summary": final_answer}, _dbg=src)
        emit(src, "note",
             f"completed '{task.get('title', task['id'])}' "
             f"(steps={state['steps']}, calls={state['tool_calls_made']})",
             detail=final_answer)
    prior = list(state.get("completed_task_titles") or [])
    if task:
        prior = prior + [{"title": task.get("title", ""), "summary": final_answer[:800]}]
    return {
        "current_task": None,
        "last_completed_task": task,
        "completed_task_titles": prior,
        "messages": [],
        "final_answer": final_answer,
        "ctx_tokens": new_ctx,
        "status": "",
        "task_ledger": None,
        "last_observation": None,
        "observation_retries": 0,
        "no_progress_cycles": 0,
        "last_confirmed_findings": preserved_findings,
        # Carry the self-review's per-finding verdicts to the pivot node so it gates board
        # facts to confirmed bullets only (no second model call). None on the fail-open path.
        "last_findings_verification": findings_verification_state,
    }
