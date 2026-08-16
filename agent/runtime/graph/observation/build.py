from __future__ import annotations

"""Assembles the observation the interpret node reasons over."""

from ...analysis.query_memo import extract_hit_count

from .digest import _artifact_labels, _evidence_digest, _evidence_snapshots, _orientation_facts, _volume_regimes
from .events import _event_ids
from .pivots import _dedupe, _dedupe_pivots, _pivot_candidates_from_orientation, _pivot_candidates_from_snapshot
from .signals import _discriminator_from_result, _error_recovery, _recommended_moves, _signals_for_result
from .trials import _EVIDENCE_TOOLS, _SEARCH_TOOLS, _STRONG_SIGNALS, _load, _tool_query_focus, _tool_time_window, _trial_outcome, _trial_record


def build_observation(
    tool_runs: list[dict],
    *,
    prior_observation: dict | None = None,
    objective: str = "",
) -> dict:
    """Summarize one tool batch into a normalized observation contract."""
    tools = [str(run.get("name") or "") for run in tool_runs]
    evidence_tools_used = {
        name
        for name in tools
        if name in _EVIDENCE_TOOLS
        and not run_is_error(next(r for r in tool_runs if r.get("name") == name))
    }
    signals: list[str] = []
    event_ids: list[str] = []
    new_artifacts: list[str] = []
    evidence_snapshots: list[dict] = []
    orientation_facts: list[dict] = []
    pivot_candidates: list[dict] = []
    volume_regimes: list[dict] = []
    error_recoveries: list[dict] = []
    summaries: list[str] = []
    hit_counts: list[int] = []
    discriminators: list[dict] = []
    time_windows: list[dict] = []
    query_focuses: list[dict] = []
    trials: list[dict] = []

    for run in tool_runs:
        tool_name = str(run.get("name") or "")
        args = run.get("args") or {}
        window = _tool_time_window(tool_name, args)
        if window:
            time_windows.append(window)
        focus = _tool_query_focus(tool_name, args)
        if focus:
            query_focuses.append(focus)
        raw = run.get("raw")
        obj = _load(raw)
        recovery = _error_recovery(tool_name, raw)
        if recovery:
            error_recoveries.append(recovery)
            signals.append(str(recovery.get("signal") or "TOOL_ERROR"))
            summaries.append(f"{tool_name} error: {recovery.get('signal')}")
            trial = _trial_record(focus, window, "error", None)
            if trial:
                trials.append(trial)
            continue
        tool_signals = _signals_for_result(
            tool_name, raw, obj, evidence_tools_used=evidence_tools_used
        )
        signals.extend(tool_signals)
        run_hits = extract_hit_count(raw) if tool_name in _SEARCH_TOOLS else None
        # Compute the event snapshots once (also reused below): the trial keeps a small
        # semantic digest of what THIS query retrieved so its meaning survives after the
        # events leave the current observation window.
        snapshots = _evidence_snapshots(tool_name, obj)
        trial = _trial_record(
            focus,
            window,
            _trial_outcome(
                tool_signals, run_hits, is_error=False, has_events=bool(_event_ids(obj))
            ),
            run_hits,
            evidence=_evidence_digest(snapshots),
        )
        if trial:
            trials.append(trial)
        if tool_name in _SEARCH_TOOLS and isinstance(obj, dict):
            hits = extract_hit_count(raw)
            if hits is not None:
                hit_counts.append(hits)
                summaries.append(f"{tool_name}={hits} hit(s)")
            disc = _discriminator_from_result(obj)
            if disc:
                discriminators.append(disc)
        elif tool_name == "get_event_volume" and isinstance(obj, dict):
            total = int(obj.get("total") or 0)
            summaries.append(f"get_event_volume={total} event(s)")
            regimes = _volume_regimes(obj)
            if regimes:
                summaries.append(f"regimes={len(regimes)}")
        event_ids.extend(_event_ids(obj))
        facts = _orientation_facts(tool_name, obj)
        evidence_snapshots.extend(snapshots)
        orientation_facts.extend(facts)
        for snapshot in snapshots:
            pivot_candidates.extend(_pivot_candidates_from_snapshot(snapshot))
        for fact in facts:
            pivot_candidates.extend(_pivot_candidates_from_orientation(fact))
        volume_regimes.extend(_volume_regimes(obj))
        new_artifacts.extend(_artifact_labels(run.get("artifacts") or []))

    evidence_markers = _dedupe([f"event:{eid}" for eid in event_ids] + new_artifacts)
    signals = _dedupe(signals)

    evidence_queries = sum(
        1
        for run in tool_runs
        if str(run.get("name") or "") in _EVIDENCE_TOOLS and not run_is_error(run)
    )
    if evidence_queries == 0:
        signals = _dedupe(signals + ["ORIENTATION_ONLY"])
    if error_recoveries and "ORIENTATION_ONLY" in signals:
        signals = [s for s in signals if s != "ORIENTATION_ONLY"]

    if "EMPTY" in signals and any(s in signals for s in ("TRUNCATED", "FLOODED")):
        signals = [s for s in signals if s != "EMPTY"]

    prior_markers = set((prior_observation or {}).get("evidence_markers") or [])
    if evidence_queries > 0 and not evidence_markers:
        if (
            prior_observation
            and (prior_observation.get("objective") or "") == objective
        ):
            signals = _dedupe(signals + ["NO_NEW_EVIDENCE"])
    elif prior_markers and set(evidence_markers).issubset(prior_markers):
        if (
            prior_observation
            and (prior_observation.get("objective") or "") == objective
        ):
            signals = _dedupe(signals + ["NO_NEW_EVIDENCE"])

    advanced_objective = bool(evidence_markers) and not any(
        s in _STRONG_SIGNALS for s in signals
    )
    if (
        evidence_queries > 0
        and "EMPTY" not in signals
        and "WRONG_REPRESENTATION" not in signals
    ):
        advanced_objective = advanced_objective or not any(
            s in signals for s in ("TRUNCATED", "SATURATED", "FLOODED")
        )

    evidence_digest = _evidence_digest(evidence_snapshots)
    summary = ", ".join(summaries[:3]) if summaries else "no concrete evidence returned"
    # Fold the top retrieved event into the propagated summary so semantic content
    # (not just a hit count) survives into the ledger, the interpret note, and the
    # deterministic fallback path — the model-independent channel.
    if evidence_digest:
        summary = f"{summary} — top: {evidence_digest[0][:200]}"
    if signals:
        summary = f"{summary}; signals={', '.join(signals)}"

    # The flood's deviation axis (prefer one whose minority-event sample was returned).
    discriminator = next(
        (d for d in discriminators if d.get("sample_event_ids")),
        discriminators[0] if discriminators else None,
    )
    moves = _recommended_moves(signals)
    if (
        discriminator
        and discriminator.get("field")
        and discriminator.get("minority") is not None
    ):
        values = ", ".join(
            str(v) for v in (discriminator.get("minority_values") or [])[:8]
        )
        sample_ids = ", ".join(
            str(v) for v in (discriminator.get("sample_event_ids") or [])[:6]
        )
        sample_part = f" sample events: {sample_ids};" if sample_ids else ""
        moves = moves + [
            f"the residue is on `{discriminator['field']}` with minority candidates "
            f"{values or discriminator['minority']};{sample_part} inspect and decode the "
            "provided minority sample first, rank candidates by semantic fit to the task "
            f"objective, then query `{discriminator['field']}=<chosen value>` or "
            f"`must_not {discriminator['field']}={discriminator['dominant']}` only if the "
            "sample is insufficient or scope must be enumerated"
        ]

    return {
        "objective": objective,
        "tools": tools,
        "evidence_queries": evidence_queries,
        "advanced_objective": advanced_objective,
        "signals": signals,
        "summary": summary,
        "discriminator": discriminator,
        "recommended_moves": moves,
        "error_recoveries": error_recoveries[:6],
        "new_artifacts": new_artifacts[:8],
        "event_ids": event_ids[:8],
        "evidence_markers": evidence_markers[:12],
        "evidence_digest": evidence_digest,
        "evidence_snapshots": evidence_snapshots[:8],
        "orientation_facts": orientation_facts[:8],
        "pivot_candidates": _dedupe_pivots(pivot_candidates),
        "volume_regimes": volume_regimes[:8],
        "hit_counts": hit_counts[:8],
        "time_windows": time_windows[:8],
        "query_focuses": query_focuses[:8],
        "trials": trials[:8],
    }


def run_is_error(run: dict) -> bool:
    raw = run.get("raw")
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("Error:"):
            return True
    obj = _load(raw)
    return isinstance(obj, dict) and "error" in obj
