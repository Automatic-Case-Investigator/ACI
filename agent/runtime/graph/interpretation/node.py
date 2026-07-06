"""The `interpret` graph node and its ledger-application + compaction glue."""
from __future__ import annotations

from ...infra.logbus import emit, src_label
from ..board import _format_board_context
from ..state import AgentState
from ..toolio import _call, _emit_node_entry, _tmap
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from ._const import _CONTINUE_ACTIONS, _DEFAULT_STOP_CONDITION, _MAX_REFINE_STREAK, _READY_EVIDENCE_KEEP, _STUCK_RETRIES
from .ledger import _coerce_confirmed_findings, _coerce_query_focuses, _coerce_string_list, _coerce_time_windows, _coerce_trials, _confirmed_findings_from_observation, _default_ledger, _detect_focus_stagnation, _detect_window_stagnation, _merge_confirmed_findings, _merge_query_trials, _merge_recent_query_focuses, _merge_recent_time_windows, _merge_string_lists, _parse_interpretation_text
from .pivots import _coerce_adjacency, _coerce_pivot, _coerce_pivots, _update_pivot_state
from .decisions import _action_from_review, _compose_instruction, _evidence_state_from_observation, _exhausted_shape, _fallback_interpretation, _forbidden_repeats, _reconcile_terminal_action, _should_assess, _triage_ready_to_complete
from .prompt import _batch_tool_outputs, _interpret_context, _interpret_system_prompt


def _apply_model_ledger(
    ledger: dict, observation: dict, parsed: dict, action: str, observation_retries: int, is_triage: bool
) -> tuple[dict, str]:
    ready = _should_assess(observation, action, observation_retries, is_triage=is_triage)
    evidence_state = str(parsed.get("evidence_state") or "").strip() or _evidence_state_from_observation(
        observation, action, ready
    )
    updated = {
        "objective": ledger.get("objective") or "",
        "hypothesis": str(parsed.get("hypothesis") or ledger.get("hypothesis") or "").strip(),
        "evidence_summary": str(parsed.get("what_showed") or observation.get("summary") or "").strip(),
        "stop_state": str(parsed.get("stop_state") or ("continue" if not ready else "complete")).strip().lower(),
        "next_action": action,
        "next_step_instruction": "",
        # Keep the model's forward-stage target, else persist the prior one so the
        # "what happened next on the same asset" pressure survives across cycles.
        "next_adjacent_evidence_path": _coerce_adjacency(parsed.get("next_adjacent_evidence_path"))
        or _coerce_adjacency(ledger.get("next_adjacent_evidence_path")),
        "forbidden_repeats": _merge_string_lists(
            ledger.get("forbidden_repeats"),
            parsed.get("forbidden_repeats") or _forbidden_repeats(observation),
            limit=8,
        ),
        "blocker": str(parsed.get("blocker") or "").strip(),
        "evidence_state": evidence_state,
        "evidence_found": _merge_string_lists(ledger.get("evidence_found"), parsed.get("evidence_found")),
        "confirmed_findings": _merge_confirmed_findings(
            ledger.get("confirmed_findings"),
            _coerce_confirmed_findings(parsed.get("confirmed_findings"))
            or _confirmed_findings_from_observation(observation, parsed),
        ),
        "remaining_gaps": _coerce_string_list(parsed.get("remaining_gaps"))
        or _coerce_string_list(ledger.get("remaining_gaps")),
        "stop_condition": str(
            parsed.get("stop_condition") or ledger.get("stop_condition") or _DEFAULT_STOP_CONDITION
        ).strip(),
        "stop_reason": str(parsed.get("stop_reason") or ledger.get("stop_reason") or "").strip(),
        "active_pivots": _coerce_pivots(ledger.get("active_pivots")),
        "primary_pivot": _coerce_pivot(ledger.get("primary_pivot")),
        "recent_time_windows": _coerce_time_windows(ledger.get("recent_time_windows")),
        "recent_query_focuses": _coerce_query_focuses(ledger.get("recent_query_focuses")),
        "query_trials": _coerce_trials(ledger.get("query_trials")),
    }
    (
        updated["active_pivots"],
        updated["primary_pivot"],
        updated["next_pivot_strategy"],
        updated["why_current_pivot_failed"],
    ) = _update_pivot_state(updated, observation, action, parsed=parsed)
    updated["next_step_instruction"] = _compose_instruction(
        observation, action, ready, str(parsed.get("next_step_instruction") or ""), updated
    )
    return updated, ("ready_to_assess" if ready else "needs_more_work")
async def _investigation_context(state: AgentState, tools: list) -> str:
    if state["agent_name"] != "investigation":
        return ""
    from ..nodes_loop import _queue_context_for_state

    queue_context = await _queue_context_for_state(state, tools)
    board_context = ""
    get_board_fn = _tmap(tools).get("get_board")
    if get_board_fn:
        raw = await _call(get_board_fn, {})
        board_context = _format_board_context(raw)
    return (board_context + queue_context).strip()
def _compact_messages_after_interpret(state: AgentState, ledger: dict, observation: dict) -> list:
    """Ready-to-assess handoff context: the interpreted summary PLUS the recent tool-result
    evidence (bounded), MINUS the seed task checklist HumanMessage.

    `assess` runs next and needs the actual tool evidence to (a) confirm a SIEM query ran
    before completing and (b) synthesize the mandated report — when this reached the ready
    path via interpret's `stop_completed`, the model never wrote a report itself, so the
    evidence must survive for `assess` to build one from. Dropping all tool messages here
    (the old behavior) made `assess` see zero SIEM tools: it false-positived the "no SIEM
    query" guard, burned the reflection-retry budget re-injecting, and then skipped the
    report-shape repair, so the bare ledger summary was persisted as the "report" with no
    ## Investigation Plan for the seeder. We keep the recent evidence exchanges (bounded to
    avoid context blow-up) and drop only the seed checklist HumanMessage (whose numbered
    steps a weak model would replay).
    """
    existing = list(state.get("messages") or [])
    compact: list = []
    system = next((m for m in existing if isinstance(m, SystemMessage)), None)
    if system is not None:
        compact.append(system)
    # The recent tool-call / tool-result exchanges — the evidence assess synthesizes from.
    evidence = [m for m in existing if isinstance(m, (AIMessage, ToolMessage))]
    evidence = evidence[-_READY_EVIDENCE_KEEP:]

    summary_lines = [
        "Interpreted observation summary:",
        f"- Objective: {ledger.get('objective') or '(unspecified)'}",
        f"- Latest observation: {ledger.get('evidence_summary') or observation.get('summary') or '(none)'}",
        f"- Evidence state: {ledger.get('evidence_state') or 'unknown'}",
        f"- Next action: {ledger.get('next_action') or 'retrieve_specific_event'}",
        f"- Next step: {ledger.get('next_step_instruction') or 'follow the most direct evidence path'}",
        f"- Stop state: {ledger.get('stop_state') or 'continue'}",
        f"- Blocker: {ledger.get('blocker') or 'none'}",
    ]
    pivot = _coerce_pivot(ledger.get("primary_pivot"))
    if pivot:
        summary_lines.append(
            "- Primary pivot: "
            f"{pivot.get('field')}={pivot.get('value')} "
            f"({pivot.get('source_level')}, {pivot.get('role')}, "
            f"{pivot.get('confidence')}, failures={pivot.get('failure_count')})"
        )
    evidence_found = _coerce_string_list(ledger.get("evidence_found"), limit=8)
    if evidence_found:
        summary_lines.append("- Evidence found: " + "; ".join(evidence_found))
    confirmed = _coerce_confirmed_findings(ledger.get("confirmed_findings"), limit=8)
    if confirmed:
        summary_lines.append("- Confirmed findings: " + "; ".join(f["summary"] for f in confirmed))
    gaps = _coerce_string_list(ledger.get("remaining_gaps"), limit=8)
    if gaps:
        summary_lines.append("- Remaining gaps: " + "; ".join(gaps))
    if ledger.get("stop_reason"):
        summary_lines.append(f"- Stop reason: {ledger.get('stop_reason')}")
    # Summary first (interpreted narrative as context), then the raw evidence LAST so
    # `assess` sees a ToolMessage as the tail and routes into report synthesis from real
    # evidence instead of mistaking the ledger summary for the finished report.
    compact.append(HumanMessage(content="\n".join(summary_lines)))
    compact.extend(evidence)
    return compact
def _format_interpret_note(ledger: dict, observation: dict, status: str) -> str:
    lines = [
        f"Status: {status}",
        f"What the last batch showed: {ledger.get('evidence_summary') or observation.get('summary') or '(none)'}",
        f"Did it advance the task: {'yes' if observation.get('advanced_objective') else 'no'}",
        f"Success criteria: {ledger.get('stop_condition') or '(none)'}",
        f"Working hypothesis: {ledger.get('hypothesis') or '(none)'}",
        f"What remains unproven or blocked: {ledger.get('blocker') or '(none)'}",
        f"Suggested next direction: {ledger.get('next_step_instruction') or '(none)'}",
        f"Stop state: {ledger.get('stop_state') or 'continue'}",
    ]
    pivot = _coerce_pivot(ledger.get("primary_pivot"))
    if pivot:
        lines.append(
            "Current pivot: "
            f"{pivot.get('field')}={pivot.get('value')} "
            f"({pivot.get('source_level')}, {pivot.get('role')}, failures={pivot.get('failure_count')})"
        )
    trials = _coerce_trials(ledger.get("query_trials"))
    if trials:
        by_outcome: dict[str, int] = {}
        for t in trials:
            by_outcome[t["outcome"]] = by_outcome.get(t["outcome"], 0) + t.get("count", 1)
        tally = ", ".join(f"{k}={v}" for k, v in sorted(by_outcome.items()))
        lines.append(f"Trials: {len(trials)} distinct ({tally})")
    return "\n".join(lines)
async def interpret(state: AgentState, config) -> dict:
    """Interpret the most recent tool-result batch before allowing another action."""
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "interpret", state)
    observation = state.get("last_observation") or {}
    task = state.get("current_task")
    ledger = dict(state.get("task_ledger") or _default_ledger(task))
    tools = config["configurable"]["tools"]
    model = config["configurable"].get("model")
    observation_retries = state.get("observation_retries", 0) or 0
    is_triage = state["agent_name"] == "triage"
    extra_context = await _investigation_context(state, tools)

    window_stagnation = _detect_window_stagnation(ledger, observation, observation_retries)
    if window_stagnation:
        signals = [*(observation.get("signals") or [])]
        if "WINDOW_STAGNANT" not in signals:
            signals.append("WINDOW_STAGNANT")
        observation = {
            **observation,
            "signals": signals,
            "window_stagnation": window_stagnation,
        }
    focus_stagnation = _detect_focus_stagnation(ledger, observation, observation_retries)
    if focus_stagnation:
        signals = [*(observation.get("signals") or [])]
        if "FOCUS_STAGNANT" not in signals:
            signals.append("FOCUS_STAGNANT")
        observation = {
            **observation,
            "signals": signals,
            "focus_stagnation": focus_stagnation,
        }
    next_recent_windows = _merge_recent_time_windows(
        ledger.get("recent_time_windows"),
        observation.get("time_windows"),
        advanced=bool(observation.get("advanced_objective")),
    )
    next_recent_focuses = _merge_recent_query_focuses(
        ledger.get("recent_query_focuses"),
        observation.get("query_focuses"),
        advanced=bool(observation.get("advanced_objective")),
    )
    # The outcome-annotated trial history accumulates across the WHOLE task (not reset on
    # advancement) so the interpreter can reason over every discriminator/window it has
    # tried and what each returned.
    next_query_trials = _merge_query_trials(
        ledger.get("query_trials"), observation.get("trials")
    )

    # Stuck detection: the same direction has returned nothing for _STUCK_RETRIES cycles.
    # Inject a STUCK signal so the prompt, the fallback, and _default_instruction all steer
    # toward a change of approach instead of echoing the dead plan. (Harmless if the task
    # then completes: _compose_instruction returns the report instruction when ready.)
    stuck = observation_retries >= _STUCK_RETRIES and not observation.get("advanced_objective")
    if stuck and "STUCK" not in (observation.get("signals") or []):
        observation = {**observation, "signals": [*(observation.get("signals") or []), "STUCK"]}

    updated_ledger, status = _fallback_interpretation(
        ledger, observation, observation_retries, is_triage=is_triage
    )
    # Confirmed compromise indicators the decode layer already boarded (deterministic, and
    # independent of the 24KB tool-result cap / raw position that can hide the source event
    # from the model). Surfaced prominently so interpret dispositions them per-cycle.
    try:
        from ..validation import _board_compromise_facts
        compromise_facts = _board_compromise_facts(state)
    except Exception:
        compromise_facts = []
    if model is not None:
        try:
            tool_outputs = _batch_tool_outputs(state.get("messages") or [])
            response = await model.ainvoke([
                SystemMessage(content=_interpret_system_prompt()),
                HumanMessage(content=_interpret_context(
                    task, ledger, observation, extra_context, tool_outputs, compromise_facts
                )),
            ])
            parsed = _parse_interpretation_text(getattr(response, "content", "") or "")
            if isinstance(parsed, dict):
                action = _action_from_review(parsed, observation)
                if (
                    is_triage
                    and _triage_ready_to_complete(observation)
                    and action in _CONTINUE_ACTIONS
                ):
                    action = "stop_completed"
                updated_ledger, status = _apply_model_ledger(
                    ledger, observation, parsed, action, observation_retries, is_triage
                )
        except Exception as exc:
            emit(src, "warning", "interpretation model failed; using deterministic fallback", detail=str(exc))

    reconciled_action, status = _reconcile_terminal_action(
        observation, str(updated_ledger.get("next_action") or ""), status, updated_ledger
    )
    updated_ledger["next_action"] = reconciled_action
    ready = status == "ready_to_assess"
    # On a STUCK cycle, break the echo deterministically: drop the persistent forward target
    # (it is what re-injects the dead direction), record the exhausted shape, and DISCARD the
    # model's echoed instruction (`provided=""`) so `_compose_instruction` falls to the STUCK
    # change-of-approach default rather than restating the same suggestion.
    if stuck and not ready:
        updated_ledger["next_adjacent_evidence_path"] = {}
        exhausted = _exhausted_shape(observation, ledger)
        if exhausted:
            updated_ledger["forbidden_repeats"] = _merge_string_lists(
                updated_ledger.get("forbidden_repeats"), [exhausted], limit=8
            )
    provided = "" if (stuck and not ready) else (updated_ledger.get("next_step_instruction") or "")
    # Recompose the instruction whenever the action changed under reconciliation, or the
    # task is wrapping up, so the imperative always matches the final action.
    updated_ledger["next_step_instruction"] = _compose_instruction(
        observation, reconciled_action, ready, provided, updated_ledger
    )
    updated_ledger["recent_time_windows"] = next_recent_windows
    updated_ledger["recent_query_focuses"] = next_recent_focuses
    updated_ledger["query_trials"] = next_query_trials
    if not updated_ledger.get("forbidden_repeats"):
        updated_ledger["forbidden_repeats"] = _forbidden_repeats(observation)
    if ready:
        # A task ready to assess has no outstanding blocker; drop any stale text.
        updated_ledger["blocker"] = ""
        if not updated_ledger.get("stop_reason"):
            updated_ledger["stop_reason"] = (
                updated_ledger.get("evidence_summary") or observation.get("summary") or ""
            )

    # Refine-loop breaker: narrowing the same thread again and again without advancing the
    # objective means the answer is not in more narrowing — force a pivot to a different
    # entity/class/window. Deterministic backstop for the interpreter over-selecting
    # refine_query. Only triggers on a NON-advancing streak, so a productive series of
    # refinements is never interrupted.
    refine_streak = state.get("refine_streak", 0) or 0
    if (
        not ready
        and updated_ledger.get("next_action") == "refine_query"
        and not observation.get("advanced_objective")
    ):
        if refine_streak >= _MAX_REFINE_STREAK:
            updated_ledger["next_action"] = "pivot_entity"
            updated_ledger["blocker"] = (
                (updated_ledger.get("blocker") or "")
                + " | refined this thread repeatedly without progress — PIVOT to a different "
                "entity, behaviour class, or time window (the evidence is not in more "
                "narrowing here)."
            ).strip(" |")
            updated_ledger["next_step_instruction"] = _compose_instruction(
                observation, "pivot_entity", False, ledger=updated_ledger
            )
            refine_streak = 0
        else:
            refine_streak += 1
    else:
        refine_streak = 0

    no_new_evidence = "NO_NEW_EVIDENCE" in set(observation.get("signals") or [])
    next_retries = observation_retries + 1 if (no_new_evidence or not observation.get("advanced_objective")) else 0

    emit(
        src,
        "note",
        f"interpret: {updated_ledger.get('next_action')} ({status})",
        detail=_format_interpret_note(updated_ledger, observation, status),
    )
    result = {
        "task_ledger": updated_ledger,
        "last_observation": observation,
        "status": status,
        "observation_retries": next_retries,
        "refine_streak": refine_streak,
    }
    if ready:
        # Wrap-up path: keep the compacted, interpreted evidence for the report writer.
        result["messages"] = _compact_messages_after_interpret(state, updated_ledger, observation)
    else:
        # Continuation path: clear the message history so `think` re-enters its
        # ledger-driven rebuild and re-applies next_step_instruction + forbidden_repeats
        # + "do not restart the checklist" on EVERY turn. Replaying the compacted history
        # here re-injected the original task checklist as message[1], and smaller models
        # restarted orientation from step 1 each cycle. The durable ledger carries all
        # evidence forward, so nothing is lost by dropping the message history here.
        result["messages"] = []
    return result
