"""Next-action decision logic and instruction composition for the interpret loop."""
from __future__ import annotations


from ._const import _CONTINUE_ACTIONS, _DEFAULT_STOP_CONDITION, _FORCE_CONTINUE_SIGNALS, _REPORT_INSTRUCTION, _TERMINAL_ACTIONS
from .ledger import _coerce_query_focuses, _coerce_string_list, _coerce_time_windows, _coerce_trials, _confirmed_findings_from_observation, _merge_confirmed_findings
from .pivots import _coerce_adjacency, _coerce_pivot, _pivot_instruction_fragment, _update_pivot_state


def _next_action_from_signals(obs: dict) -> str:
    signals = set(obs.get("signals") or [])
    if "WINDOW_STAGNANT" in signals:
        return "profile_window"
    if "FOCUS_STAGNANT" in signals:
        return "pivot_entity"
    if "INVALID_TIME_WINDOW" in signals:
        return "retrieve_specific_event"
    if "TOOL_ERROR" in signals:
        return "retrieve_specific_event"
    if "TRUNCATED" in signals or "FLOODED" in signals:
        return "refine_query"
    if "SATURATED" in signals:
        return "profile_window"
    if "WRONG_REPRESENTATION" in signals:
        return "retrieve_specific_event"
    if "EMPTY" in signals or "NO_NEW_EVIDENCE" in signals:
        return "pivot_entity"
    has_concrete_evidence = bool((obs.get("event_ids") or []) or (obs.get("evidence_markers") or []))
    if obs.get("advanced_objective") and has_concrete_evidence:
        return "stop_completed"
    return "retrieve_specific_event"
def _action_from_review(parsed: dict, observation: dict) -> str:
    """Resolve the next action from the model's review.

    Completion is a semantic claim only the model can make — by mapping the task's
    success criteria to evidence — so a terminal action must originate from the model's
    own vote (in any of its shapes: the text template's `stop_state`, or the JSON
    contract's `next_action`/`progress_status`). Deterministic signals may VETO a
    completion downstream (`_should_assess`, `_reconcile_terminal_action`); they never
    INITIATE one. (Diagnosed: a task completed after one retrieval because signals
    escalated "evidence appeared" into `stop_completed` over the model's continue vote.)
    """
    stop_state = str(parsed.get("stop_state") or "").strip().lower()
    if stop_state == "complete":
        return "stop_completed"
    if stop_state == "negative":
        return "stop_negative"
    claimed = str(parsed.get("next_action") or "").strip().lower()
    progress = str(parsed.get("progress_status") or "").strip().lower()
    if not stop_state:
        if claimed == "stop_negative" or progress == "exhausted":
            return "stop_negative"
        if claimed == "stop_completed" or progress == "complete":
            return "stop_completed"
    action = _next_action_from_signals(observation)
    if action in _TERMINAL_ACTIONS:
        # The model voted continue: keep its own continue action when it named a valid
        # one, otherwise fall back to the default retrieval step.
        return claimed if claimed in _CONTINUE_ACTIONS else "retrieve_specific_event"
    return action
def _should_assess(obs: dict, action: str, observation_retries: int, is_triage: bool = False) -> bool:
    signals = set(obs.get("signals") or [])
    if action == "stop_completed":
        # Triage may hand off despite a flood on the latest batch — for triage a
        # flood/truncation is a "needs investigation" cue, not a keep-drilling one.
        # Investigation must not conclude a FINDING on a flood, and never selects
        # stop_completed under a force-continue signal in the first place.
        return is_triage or not (signals & _FORCE_CONTINUE_SIGNALS)
    if signals & _FORCE_CONTINUE_SIGNALS:
        return False
    if action == "stop_negative":
        return observation_retries >= 1 or "NO_NEW_EVIDENCE" in signals
    return False
def _triage_ready_to_complete(obs: dict) -> bool:
    """Triage needs enough SCOPED evidence to summarize and hand off, not exhaustive
    closure. Completion is judged on accumulated evidence, NOT on whether the latest
    batch was signal-clean: a flood / truncation / saturation is, for triage, a
    'needs investigation' cue, so it does NOT block the handoff once concrete evidence
    exists. Only a batch that is still pure orientation (no evidence yet) or actively
    drifting to the wrong representation keeps triage working.
    """
    signals = set(obs.get("signals") or [])
    if "ORIENTATION_ONLY" in signals or "WRONG_REPRESENTATION" in signals:
        return False
    if int(obs.get("evidence_queries") or 0) <= 0:
        return False
    if obs.get("small_scoped_evidence") or (obs.get("event_ids") or []) or (obs.get("evidence_markers") or []):
        return True
    # Triage is allowed to hand off on scoped aggregate evidence: a profile, capped hit
    # set, or zero-result query can be the correct triage result when the report names
    # the uncertainty and turns it into investigation work. Investigation still needs
    # direct task evidence before concluding.
    return bool(obs.get("advanced_objective") and (obs.get("summary") or obs.get("recommended_moves")))
def _evidence_state_from_observation(observation: dict, action: str, ready: bool) -> str:
    signals = set(observation.get("signals") or [])
    if ready and action == "stop_completed":
        return "sufficient_handoff"
    if ready and action == "stop_negative":
        return "confirmed_negative"
    if observation.get("event_ids") or observation.get("evidence_markers"):
        return "scoped_hits"
    if "INVALID_TIME_WINDOW" in signals or "TOOL_ERROR" in signals:
        return "tool_error_recovery"
    if "ORIENTATION_ONLY" in signals or int(observation.get("evidence_queries") or 0) <= 0:
        return "orientation"
    return "aggregate_signal"
def _invalid_time_recovery_instruction(observation: dict) -> str:
    recoveries = [
        item for item in (observation.get("error_recoveries") or [])
        if isinstance(item, dict) and item.get("signal") == "INVALID_TIME_WINDOW"
    ]
    if not recoveries:
        return ""
    recovery = recoveries[-1]
    requested = recovery.get("requested_window") if isinstance(recovery.get("requested_window"), dict) else {}
    required = recovery.get("required_window") if isinstance(recovery.get("required_window"), dict) else {}
    requested_text = (
        f"{requested.get('from')} to {requested.get('to')}"
        if requested.get("from") and requested.get("to")
        else "an out-of-scope time range"
    )
    required_text = (
        f"{required.get('from')} to {required.get('to')}"
        if required.get("from") and required.get("to")
        else "the claimed task's absolute incident window"
    )
    return (
        f"The previous SIEM call was blocked because it used {requested_text}. "
        f"Recover by issuing the same evidence query inside {required_text}. "
        "Do not invent a new year, do not use TheHive createdAt/_createdAt, and do not "
        "change investigative direction until this corrected task-window query has run."
    )
def _exhausted_shape(observation: dict, ledger: dict) -> str:
    """A short label for the dead query direction, recorded in forbidden_repeats so it is
    not re-proposed and downstream reads it as a settled negative."""
    pivot = _coerce_pivot(ledger.get("primary_pivot"))
    if pivot and pivot.get("field") and pivot.get("value"):
        return f"{pivot['field']}={pivot['value']} (returned nothing repeatedly — abandon this shape)"
    adj = ledger.get("next_adjacent_evidence_path") or {}
    if isinstance(adj, dict):
        label = " ".join(str(adj.get(k) or "") for k in ("entity", "representation_hint")).strip()
        if label:
            return f"{label} (returned nothing repeatedly — abandon this shape)"
    return ""
def _default_instruction(observation: dict, action: str) -> str:
    signals = set(observation.get("signals") or [])
    regimes = observation.get("volume_regimes") or []
    if "WINDOW_STAGNANT" in signals:
        stagnation = observation.get("window_stagnation") or {}
        span = stagnation.get("covered_span") if isinstance(stagnation, dict) else {}
        span_text = (
            f" Covered span: {span.get('from')} to {span.get('to')}."
            if isinstance(span, dict) and span.get("from") and span.get("to")
            else ""
        )
        return (
            "You have repeatedly queried the same covered span without materially advancing "
            "the objective. Treat the current time slice as provisionally exhausted. Choose "
            "the next adjacent or task-relevant uncovered window from the burst map or "
            "evidence edge, and explain why that direction tests the objective. Do not merely "
            f"widen around the same center.{span_text}"
        )
    if "FOCUS_STAGNANT" in signals:
        stagnation = observation.get("focus_stagnation") or {}
        repeated = stagnation.get("repeated_focuses") if isinstance(stagnation, dict) else []
        focus_text = ", ".join(
            str(item.get("focus"))
            for item in repeated[:3]
            if isinstance(item, dict) and item.get("focus")
        )
        focus_part = f" Repeated focus: {focus_text}." if focus_text else ""
        return (
            "You have repeatedly used the same keyword, rule, or profile-field anchor without "
            "materially advancing the objective. Treat that lexical/discriminator focus as "
            "provisionally exhausted. Change the evidence axis now: move to an adjacent "
            "task-relevant time window, a different behavior class, or a raw event edge that "
            "tests the objective. Do not merely combine the same keyword or rule id with a "
            f"slightly different filter.{focus_part}"
        )
    # STUCK takes precedence over everything: the same direction has returned nothing for
    # several cycles, so any content-based instruction would just echo the dead plan.
    if "STUCK" in signals:
        return (
            "This exact query direction has returned nothing several times in a row — it is "
            "exhausted; do NOT repeat it. Change the APPROACH, not the wording: switch the "
            "field (e.g. data.srcuser↔data.dstuser, or src↔dst IP), `profile_field` on "
            "`rule.groups`/`rule.id` to discover the REAL rule that fired (do not re-guess a "
            "rule.id number), widen the time window, or question the premise (did this event "
            "occur on THIS host/entity at all — try the destination host or the adjacent phase). "
            "Keep the objective; abandon this tactic."
        )
    invalid_time_instruction = _invalid_time_recovery_instruction(observation)
    if invalid_time_instruction:
        return invalid_time_instruction
    if "TOOL_ERROR" in signals:
        recoveries = observation.get("error_recoveries") or []
        latest = next((item for item in reversed(recoveries) if isinstance(item, dict)), {})
        error_text = str(latest.get("error") or "the previous tool error").strip()
        return (
            f"The previous tool call failed: {error_text[:320]}. Recover from that concrete "
            "failure first by correcting the tool arguments or choosing the equivalent supported "
            "tool shape for the same evidence target. Do not restart orientation."
        )
    # A flooded result whose deviation axis the tool already isolated: route it into
    # the obeyed channel so the agent reads the sample before querying the flood head.
    disc = observation.get("discriminator")
    if isinstance(disc, dict) and disc.get("field") and disc.get("minority") is not None:
        values = ", ".join(str(v) for v in (disc.get("minority_values") or [])[:8])
        sample_ids = ", ".join(str(v) for v in (disc.get("sample_event_ids") or [])[:6])
        sample_part = f" Sample events already returned: {sample_ids}." if sample_ids else ""
        return (
            f"The result is flood-dominated, and the events differ along `{disc['field']}` "
            f"(dominant `{disc.get('dominant')}` = the scan/noise; minority candidates: "
            f"{values or disc['minority']}).{sample_part} Inspect and decode the returned "
            "minority sample now, ranking each deviation by semantic fit to the task objective "
            "rather than by rarity alone. Only run a follow-up query for a chosen minority value "
            "or `must_not` the dominant when the sample is insufficient or you need to enumerate "
            "the scope. Do NOT re-query the flooded head."
        )
    if "MULTI_REGIME" in signals and regimes:
        shown = ", ".join(
            f"{r.get('start')}→{r.get('end')} ({r.get('total')} ev)"
            for r in regimes[:3]
            if isinstance(r, dict)
        )
        return (
            "This window contains multiple candidate activity regimes. Compare them against "
            "the confirmed alert anchor in time, entity, and behavior, then drill the regime "
            "that most directly continues the evidence chain rather than the largest burst. "
            f"Candidate regimes: {shown}."
        )
    if observation.get("event_ids") or observation.get("evidence_markers"):
        return "Retrieve and interpret representative raw events from the current scoped hit set before broadening."
    if "TRUNCATED" in signals or "FLOODED" in signals:
        return (
            "Narrow by the most discriminative behavior, entity, and time window, "
            "then retrieve raw events from the reduced hit set."
        )
    if "SATURATED" in signals:
        return (
            "The active region fills the whole window. Re-profile a shorter window around the "
            "anchor timeframe instead of following the densest peak or changing the interval."
        )
    if "EMPTY" in signals or "NO_NEW_EVIDENCE" in signals:
        return (
            "Pivot to a different entity, behavior class, or adjacent time window "
            "that directly tests the stop condition."
        )
    if "ORIENTATION_ONLY" in signals:
        # Concrete push out of the orientation loop: name the tools that are already spent so
        # the model cannot justify re-running them, and command the specific first SIEM move.
        # An abstract "move to the first evidence-bearing query" loses to the seed task's
        # numbered orientation checklist; naming both sides makes the instruction win.
        return (
            "Orientation is complete — the case, alerts, patterns, baselines, and analyst "
            "feedback are already captured in the ledger. Do NOT call get_case, list_case_alerts, "
            "search_patterns, list_baseline_entities, or search_feedback again. Derive the "
            "absolute time window around the alert anchor timestamp and issue your FIRST SIEM "
            "query now (search_keyword, search, profile_field, or get_event_volume) scoped to the "
            "case's host, user, source IP, and rule family."
        )
    return "Run the highest-yield concrete evidence query for the current objective."
def _compose_instruction(
    observation: dict, action: str, ready: bool, provided: str = "", ledger: dict | None = None
) -> str:
    """The single imperative `think` follows next turn. Absorbs what used to be split
    across best_next_evidence_path / next_adjacent_evidence_path.
    """
    if ready or action in _TERMINAL_ACTIONS:
        return _REPORT_INSTRUCTION
    signals = set(observation.get("signals") or [])
    if (
        "WINDOW_STAGNANT" in signals
        or "FOCUS_STAGNANT" in signals
        or "INVALID_TIME_WINDOW" in signals
        or "TOOL_ERROR" in signals
    ):
        base = _default_instruction(observation, action)
    else:
        base = provided.strip() or _default_instruction(observation, action)
    pivot_fragment = _pivot_instruction_fragment(ledger or {})
    if pivot_fragment and pivot_fragment not in base:
        base += pivot_fragment
    repeated = ", ".join(observation.get("tools") or [])
    if repeated:
        base += (
            f" Do not restart by repeating the last tool batch ({repeated}) unless you "
            "first state why the ledger is wrong."
        )
    return base
def _forbidden_repeats(observation: dict) -> list[str]:
    tools = observation.get("tools") or []
    orientation_tools = {
        "get_case", "list_case_alerts", "search_patterns", "search_feedback",
        "list_baseline_entities",
    }
    return [tool for tool in tools if tool in orientation_tools][:8]
def _reconcile_terminal_action(observation: dict, action: str, status: str, ledger: dict) -> tuple[str, str]:
    """A terminal action (stop_*) is only honored when the gate agreed (ready). Otherwise
    demote it to a concrete continuation so the loop cannot stop on an unmet standard.
    """
    if status == "ready_to_assess" or action not in _TERMINAL_ACTIONS:
        return action, status
    if (
        action == "stop_completed"
        and (ledger.get("objective") or "").lower().startswith("triage case")
        and _triage_ready_to_complete(observation)
    ):
        return action, "ready_to_assess"
    fallback = _next_action_from_signals(observation)
    if fallback in _TERMINAL_ACTIONS:
        fallback = "retrieve_specific_event"
    return fallback, "needs_more_work"
def _fallback_interpretation(
    ledger: dict, observation: dict, observation_retries: int, is_triage: bool = False
) -> tuple[dict, str]:
    """Deterministic ledger update used when no model is configured or the model call
    fails/omits a field. Signals map to actions; the model refines the prose."""
    action = _next_action_from_signals(observation)
    if is_triage and _triage_ready_to_complete(observation):
        action = "stop_completed"
    ready = _should_assess(observation, action, observation_retries, is_triage=is_triage)

    updated = dict(ledger)
    updated["next_action"] = action
    updated["evidence_summary"] = observation.get("summary") or ""
    updated["blocker"] = "; ".join(observation.get("recommended_moves") or [])
    updated["evidence_state"] = _evidence_state_from_observation(observation, action, ready)
    (
        updated["active_pivots"],
        updated["primary_pivot"],
        updated["next_pivot_strategy"],
        updated["why_current_pivot_failed"],
    ) = _update_pivot_state(updated, observation, action)
    updated["next_step_instruction"] = _compose_instruction(observation, action, ready, ledger=updated)
    updated["stop_state"] = "complete" if ready and action == "stop_completed" else "negative" if ready else "continue"
    # Persist the prior forward-stage target; the deterministic path cannot synthesize it.
    updated["next_adjacent_evidence_path"] = _coerce_adjacency(ledger.get("next_adjacent_evidence_path"))
    updated["forbidden_repeats"] = _coerce_string_list(
        ledger.get("forbidden_repeats") or _forbidden_repeats(observation)
    )
    updated["evidence_found"] = _coerce_string_list(ledger.get("evidence_found"))
    updated["confirmed_findings"] = _merge_confirmed_findings(
        ledger.get("confirmed_findings"),
        _confirmed_findings_from_observation(observation),
    )
    updated["remaining_gaps"] = _coerce_string_list(ledger.get("remaining_gaps"))
    updated["stop_condition"] = ledger.get("stop_condition") or _DEFAULT_STOP_CONDITION
    updated["stop_reason"] = ledger.get("stop_reason") or (updated["evidence_summary"] if ready else "")
    updated["recent_time_windows"] = _coerce_time_windows(ledger.get("recent_time_windows"))
    updated["recent_query_focuses"] = _coerce_query_focuses(ledger.get("recent_query_focuses"))
    updated["query_trials"] = _coerce_trials(ledger.get("query_trials"))
    return updated, ("ready_to_assess" if ready else "needs_more_work")
