"""The `assess` node: per-task self-review, progress gating, and investigation-report synthesis."""
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
from ..toolio import _SEED_TASK_TITLE, _call, _emit_node_entry, _extract_input_tokens, _is_error_tool_result, _tmap
from ..validation import _board_compromise_facts, _unpivoted_network_iocs
from datetime import datetime, timedelta
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
import json
import re
import logging

from ._const import _EFFORT_CEILING, _EVIDENCE_TOOLS, _MAX_INVESTIGATION_RETRIES, _MAX_REFLECTION_RETRIES, _MIN_COVERAGE_GAP, _POST_CESSATION_TAIL_BINS, _SEARCH_RESULT_TOOLS
from ._shared import _finding_bullet, _findings_section_text, _merge_preserved_findings, _new_leads_section_text, _preserved_findings_from_state

log = logging.getLogger(__name__)


def _last_search_hit_count(messages: list) -> int | None:
    """Hit count of the most recent search/search_keyword tool result, or None.

    Feeds the per-task self-review as a deterministic signal: whether the task's latest
    evidence query was still at the unusable-result ceiling (i.e. never narrowed).
    """
    from ...analysis.query_memo import extract_hit_count

    for msg in reversed(messages):
        if getattr(msg, "name", "") in _SEARCH_RESULT_TOOLS:
            return extract_hit_count(getattr(msg, "content", "") or "")
    return None
def _progress_gated_decision(
    *,
    reflection_retries: int,
    evidence_queries: int,
    last_nudge_ev: int,
    tool_calls_made: int,
    max_tool_calls: int,
    steps: int,
    max_steps: int,
) -> tuple[bool, str]:
    """Whether an investigation task that the review wants to keep working on may gather
    more, and if not, why. Called only after `review.keep_working` and `not
    effort_exhausted` already hold.

    Continue while the task is CONVERGING (the last nudge produced a new evidence query),
    the run's global call/step budget remains, and a rarely-hit safety backstop is not
    exceeded. This replaces the old flat 2-retry cap so a productive task keeps gathering
    up to the effort ceiling. Returns (keep_working, stop_reason); stop_reason is "" when
    keep_working is True.
    """
    making_progress = not (reflection_retries > 0 and evidence_queries <= last_nudge_ev)
    budget_left = tool_calls_made < (max_tool_calls or 0) and steps < (max_steps or 0)
    safety_left = reflection_retries < _MAX_INVESTIGATION_RETRIES
    if making_progress and budget_left and safety_left:
        return True, ""
    return False, (
        "prior nudge produced no new evidence — avoiding churn" if not making_progress
        else "run budget exhausted" if not budget_left
        else "reflection safety cap reached"
    )
def _count_evidence_queries(messages: list) -> int:
    """Count non-error SIEM evidence-retrieval results in the task's message history.

    Orientation calls (get_case, list_tasks, get_board, search_patterns, ls/cat) are
    excluded, so a task padded with bookkeeping is not credited as deep investigation.
    """
    n = 0
    for msg in messages:
        if getattr(msg, "name", "") in _EVIDENCE_TOOLS:
            if not _is_error_tool_result(getattr(msg, "content", "") or ""):
                n += 1
    return n
def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
def _query_time_window(args: dict) -> tuple:
    """The (from, to) datetimes a search/search_keyword call targeted — from its
    `time_range` param or an embedded `@timestamp` range filter."""
    tr = args.get("time_range") or {}
    frm, to = tr.get("from"), tr.get("to")
    if not (frm and to):
        embedded = _find_timestamp_range(args.get("query"))
        if embedded:
            frm, to = embedded
    return _parse_iso(frm), _parse_iso(to)
def _unqueried_post_peak_clusters(messages: list) -> list[str]:
    """Post-peak activity clusters a `get_event_volume` surfaced but no raw
    `search`/`search_keyword` later drilled.

    A volume profile is a to-do list of windows, not a conclusion: each active bin
    flanking the spike (`pre_spike_active_bins` / `post_spike_active_bins`) is a time
    window still holding unexamined evidence (lateral movement, persistence execution,
    privesc, cleanup hide across the multi-hour active block, not just the minute after
    the peak). This returns the cluster timestamps that remain unqueried so the task
    review can keep the agent working until it drills them.
    """
    clusters: list[datetime] = []
    for m in messages:
        if getattr(m, "name", "") != "get_event_volume":
            continue
        try:
            data = json.loads(getattr(m, "content", "") or "")
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        flanking = (data.get("pre_spike_active_bins") or []) + (data.get("post_spike_active_bins") or [])
        for b in flanking:
            t = _parse_iso(b.get("time") if isinstance(b, dict) else None)
            if t:
                clusters.append(t)
    if not clusters:
        return []

    windows: list[tuple] = []
    for m in messages:
        for tc in getattr(m, "tool_calls", None) or []:
            if tc.get("name") not in _SEARCH_RESULT_TOOLS:
                continue
            frm, to = _query_time_window(tc.get("args") or {})
            if frm and to:
                windows.append((frm, to))

    out, seen = [], set()
    for c in clusters:
        if any(f <= c <= t for f, t in windows):
            continue
        key = c.strftime("%Y-%m-%dT%H:%M:%SZ")
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out[:8]
def _interval_seconds(interval: str) -> int | None:
    """Parse an OpenSearch fixed_interval string ('5m', '1h', '3600s') to seconds."""
    m = re.match(r"^\s*(\d+)\s*([smhd])\s*$", (interval or "").lower())
    if not m:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
def _merge_intervals(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    """Union overlapping/adjacent (start, end) intervals into a minimal sorted list."""
    merged: list[tuple[datetime, datetime]] = []
    for f, t in sorted(intervals):
        if merged and f <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], t))
        else:
            merged.append((f, t))
    return merged
def _unqueried_time_ranges(messages: list) -> list[str]:
    """Contiguous sub-ranges of the window the agent PROFILED with `get_event_volume`
    that no raw `search`/`search_keyword` ever covered.

    Complements `_unqueried_post_peak_clusters` (which flags discrete post-spike bins):
    this catches an investigation that DWELLS in one slice of a window it has already
    mapped as larger — the observed failure where every query clusters in the initial
    scan minutes and never advances to the hours the profile showed were active. The
    reference span is the active regime [onset, cessation] when the profile found one
    (else the full profiled bin envelope); the covered spans are the raw-search
    windows. Deterministic measurement — the reviewer decides whether an unexamined
    range is relevant to the task. The reference is extended a couple of bins PAST
    cessation so a low-volume follow-on (a payload/success just after a loud burst,
    below the histogram threshold) is flagged as an unqueried tail rather than lost.
    """
    refs: list[tuple[datetime, datetime]] = []
    for m in messages:
        if getattr(m, "name", "") != "get_event_volume":
            continue
        try:
            data = json.loads(getattr(m, "content", "") or "")
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        start = _parse_iso((data.get("onset") or {}).get("time"))
        end = _parse_iso((data.get("cessation") or {}).get("time"))
        had_regime = bool(start and end)
        if not had_regime:
            times = [
                _parse_iso(b.get("time"))
                for b in (data.get("bins") or [])
                if isinstance(b, dict)
            ]
            times = [t for t in times if t]
            if times:
                start, end = min(times), max(times)
        # Extend the reference past cessation to include the low-volume follow-on tail —
        # the payload/success often sits just past a loud burst, below the histogram's
        # active threshold, so it never shows as "active" and gets left unqueried. Skip
        # for a saturated profile (its cessation is already the window edge).
        if had_regime and end and not data.get("saturated"):
            isecs = _interval_seconds(data.get("interval") or "")
            if isecs:
                end = end + timedelta(seconds=_POST_CESSATION_TAIL_BINS * isecs)
        if start and end and end > start:
            refs.append((start, end))
    if not refs:
        return []

    covered: list[tuple[datetime, datetime]] = []
    for m in messages:
        for tc in getattr(m, "tool_calls", None) or []:
            if tc.get("name") not in _SEARCH_RESULT_TOOLS:
                continue
            frm, to = _query_time_window(tc.get("args") or {})
            if frm and to:
                covered.append((frm, to))
    merged_cov = _merge_intervals(covered)

    gaps: list[tuple[datetime, datetime]] = []
    for rs, re_ in _merge_intervals(refs):
        cursor = rs
        for cf, ct in merged_cov:
            if ct <= cursor or cf >= re_:
                continue
            if cf > cursor:
                gaps.append((cursor, min(cf, re_)))
            cursor = max(cursor, ct)
            if cursor >= re_:
                break
        if cursor < re_:
            gaps.append((cursor, re_))

    out = [
        f"{f.strftime('%Y-%m-%dT%H:%M:%SZ')}–{t.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        for f, t in gaps
        if t - f >= _MIN_COVERAGE_GAP
    ]
    return out[:6]
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
        return (resp.content or "").strip(), (_extract_input_tokens(resp) or new_ctx)
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
                new_ctx = _extract_input_tokens(synth_resp) or new_ctx
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

    # --- Per-task self-review (replaces the six-guard re-injection cascade) -------------
    # One general question replaces six special-case guards: given the task, the evidence
    # actually retrieved, and the report written — is the task genuinely DONE, or should it
    # keep working? Deterministic checks MEASURE the signals (report shape, last hit count,
    # evidence-query count, unpivoted network IOCs); the model makes the semantic judgment
    # and classifies each ## Findings bullet. Findings verdicts are stashed for the pivot
    # node's board gating. Fail-open: a model failure falls back to the regex completeness
    # check and the task completes. One `reflection_retries` cap bounds the keep-working
    # loop; `_route_assess` routes the unified `needs_more_work` status back to `think`.
    findings_verification_state: dict | None = None
    reviewable = (
        task is not None
        and _SEED_TASK_TITLE not in (task.get("title") or "").lower()
    )
    reflection_retries = state.get("reflection_retries", 0) or 0
    budget_left = reflection_retries < _MAX_REFLECTION_RETRIES

    # Triage owns no findings board or leads to review. Whether it grounded the alert in
    # real SIEM evidence is now a SEMANTIC judgment the interpret prompt enforces (the model
    # will not vote to conclude until it has profiled/retrieved/correlated real evidence or
    # capably established a negative) — there is no deterministic "did a SIEM query run"
    # re-injection here. Only the report SHAPE (an output-format concern) is repaired below.
    if reviewable and state["agent_name"] == "triage" and budget_left:
        missing_triage = _missing_triage_sections(final_answer)
        if missing_triage:
            model = config["configurable"].get("model")
            sys_prompt = config["configurable"].get("system_prompt", "")
            if model is not None:
                emit(src, "note",
                     f"task review (triage): malformed report missing {', '.join(missing_triage)} — requesting text synthesis")
                text_only = model.bind_tools([])
                try:
                    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
                    synth_msgs = _sanitize_history(
                        state["messages"] + [HumanMessage(content=(
                            "Rewrite the triage handoff as a complete text report now. Do not "
                            "make any further tool calls. Use exactly this structure:\n\n"
                            "## Triage Summary\n"
                            "## Key Evidence\n"
                            "## Investigation Plan\n\n"
                            "Do not paste raw JSON, entity dumps, or verbatim tool payloads as "
                            "report sections. Explain the case in prose and use bullet points for "
                            "concrete evidence only.\n\n"
                            "## Key Evidence must be a bullet list of concrete observations from "
                            "the retrieved tool evidence. ## Investigation Plan must be a numbered "
                            "or bulleted list. Every plan item must include an explicit absolute "
                            "time window. If an item does not have a narrower evidence-derived "
                            "range, derive it from the configured default vicinity window of "
                            f"±{vicinity_hours} hours around the anchor timestamp. End with the "
                            "diagnostic verdict JSON block."
                        ))]
                    )
                    synth_resp = await text_only.ainvoke([SystemMessage(content=sys_prompt)] + synth_msgs)
                    _sanitize_message(synth_resp)
                    synthesized = (synth_resp.content or "").strip()
                    new_ctx = _extract_input_tokens(synth_resp) or new_ctx
                    if not _missing_triage_sections(synthesized):
                        final_answer = synthesized
                        missing_triage = []
                except Exception as exc:
                    log.warning("[%s] triage shape synthesis failed: %s", state["agent_name"], exc)
            if missing_triage:
                vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
                correction = HumanMessage(content=(
                    "Your current output is not a valid triage handoff report. Rewrite it now "
                    "without making any more tool calls. Use exactly this structure:\n\n"
                    "## Triage Summary\n"
                    "## Key Evidence\n"
                    "## Investigation Plan\n\n"
                    "Do not paste raw JSON objects, entity-only blobs, or tool payloads into the "
                    "report. Summarize what they mean instead.\n\n"
                    "## Triage Summary must briefly explain what the alert/case indicates. "
                    "## Key Evidence must be bullets grounded in the tool results you already "
                    "retrieved. ## Investigation Plan must be a numbered or bulleted list, and "
                    "every item must include an explicit absolute time window. If an item does "
                    "not have a narrower evidence-derived range, derive it from the configured "
                    f"default vicinity window of ±{vicinity_hours} hours around the anchor "
                    "timestamp. End with the diagnostic verdict JSON block."
                ))
                return {
                    "current_task": task,
                    "messages": list(state["messages"]) + [correction],
                    "status": "needs_more_work",
                    "reflection_retries": reflection_retries + 1,
                    "ctx_tokens": new_ctx,
                }

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
        effort_exhausted = evidence_queries >= _EFFORT_CEILING
        # A task already at its hard per-task call cap has no budget to act on a
        # keep-working nudge: `think` has stripped its tools, so a "keep working" vote just
        # burns one more think->cap->re-synthesis cycle before the anti-churn guard concludes
        # anyway. Treat the cap as terminal here so the task concludes on the FIRST review
        # instead of churning (diagnosed: every capped task fired the cap twice).
        cap_reached = (
            state["tool_calls_made"] - state.get("task_call_floor", 0)
        ) >= _MAX_TASK_TOOL_CALLS
        # Progress-gated continuation (replaces the old flat 2-retry cap as the primary
        # limiter): keep gathering while the review wants more AND the last nudge produced
        # NEW evidence (the task is converging) AND effort + reflection-safety + global
        # budget all remain. A productive task now keeps going up to the effort ceiling
        # instead of stopping at 2 review cycles; a stalled one still concludes at once (the
        # board-driven escalation/verdict catch any compromise already on the board). This
        # is the mechanism that lets the agent make more tool calls before completing.
        if review is not None and review.keep_working and not effort_exhausted and not cap_reached:
            keep_working, stop_reason = _progress_gated_decision(
                reflection_retries=reflection_retries,
                evidence_queries=evidence_queries,
                last_nudge_ev=state.get("reflection_evidence_at_last_nudge", -1),
                tool_calls_made=state.get("tool_calls_made", 0),
                max_tool_calls=state.get("max_tool_calls") or 0,
                steps=state.get("steps", 0),
                max_steps=state.get("max_steps") or 0,
            )
            if keep_working:
                emit(src, "note",
                     f"task review: keep working after {evidence_queries} evidence "
                     f"query(ies) (cycle {reflection_retries + 1}, progress-gated)")
                correction = HumanMessage(content=review.to_feedback())
                return {
                    "current_task": task,
                    "messages": list(state["messages"]) + [correction],
                    "status": "needs_more_work",
                    "reflection_retries": reflection_retries + 1,
                    "reflection_evidence_at_last_nudge": evidence_queries,
                    "ctx_tokens": new_ctx,
                }
            # Review wanted more work but a stop condition fired — conclude, logging why.
            emit(src, "note", f"task review: keep-working declined ({stop_reason}) — concluding")

        # Deterministic evidence floor — a hard backstop independent of the model review.
        # Mirrors the triage SIEM guard above: an investigation task must touch the SIEM at
        # least once. The model-driven rule #1 is advisory and was observed concluding
        # "rule-out" tasks on cumulative board context with ZERO queries of their own (it
        # credits prior tasks' evidence as completion of this one). Fire once — retry 0 only,
        # so it cannot loop — whenever the agent oriented but never queried.
        # NOT when the task is at its call cap: `think` has stripped its tools, so the capped
        # wrap-up cycle shows 0 queries (the messages were rebuilt) even though the task ran to
        # the cap — re-injecting here just burns a second think->cap->re-synthesis cycle (the
        # residual cap-churn: the task fired its cap note twice before concluding).
        if evidence_queries == 0 and budget_left and reflection_retries == 0 and not cap_reached:
            emit(src, "note",
                 "task review: concluded without a single SIEM evidence query — re-injecting")
            correction = HumanMessage(content=(
                "You finished this task without running a single SIEM evidence query — you only "
                "oriented (read the case/board/queue/filesystem). Reading prior findings is not "
                "investigating THIS task. Query the SIEM now for evidence specific to this task's "
                "objective: profile the relevant window (`get_event_volume`), then run "
                "`search`/`search_keyword`/`profile_field` on a concrete artifact (host, user, "
                "source IP, rule family, command, file path) you confirmed exists. If the honest "
                "answer is a confirmed negative, run the query that establishes it and cite the "
                "exact zero-result query — do not infer the negative from context alone."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "needs_more_work",
                "reflection_retries": reflection_retries + 1,
                "reflection_evidence_at_last_nudge": evidence_queries,
                "ctx_tokens": new_ctx,
            }

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
            if missing and budget_left:
                emit(src, "note",
                     f"task review: report still missing section(s) {', '.join(missing)} — "
                     f"requesting finalization (retry {reflection_retries + 1}/{_MAX_REFLECTION_RETRIES})")
                correction = HumanMessage(content=(
                    "Your evidence is sufficient. Write the FINAL report now using the "
                    "mandatory three-section format:\n\n## Findings\n## Hypotheses\n## New Leads\n\n"
                    "Populate every section from the tool results above; put each confirmed "
                    "indicator (reverse shell, C2/callback, command execution) under ## Findings "
                    "as a bullet with its event ID. Use '- None.' only for a genuinely empty "
                    "section. Do not make further tool calls."
                ))
                return {
                    "current_task": task,
                    "messages": list(state["messages"]) + [correction],
                    "status": "needs_more_work",
                    "reflection_retries": reflection_retries + 1,
                    "ctx_tokens": new_ctx,
                }

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
        "reflection_retries": 0,
        "reflection_evidence_at_last_nudge": -1,
        "task_ledger": None,
        "last_observation": None,
        "observation_retries": 0,
        "no_progress_cycles": 0,
        "last_confirmed_findings": preserved_findings,
        # Carry the self-review's per-finding verdicts to the pivot node so it gates board
        # facts to confirmed bullets only (no second model call). None on the fail-open path.
        "last_findings_verification": findings_verification_state,
    }
