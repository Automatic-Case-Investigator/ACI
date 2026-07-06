"""Run finalization: `finish`, the verdict contract, verdict reassessment, and durable publication."""
from __future__ import annotations

from ....workspace.avfs_writer import write_file
from ...analysis.verdict import (
    apply_verdict_integrity,
    parse_verdict,
    validate_verdict,
)
from ...infra.avfs import reports_dir, session_note_path
from ...infra.logbus import emit, src_label
from ..publication import build_session_note as _build_publication_session_note
from ..sanitize import _sanitize_message
from ..state import AgentState
from ..synthesis import _build_investigation_summary
from ..toolio import _call, _emit_node_entry, _tmap
from langchain_core.messages import HumanMessage, SystemMessage
import asyncio
import json

from ._const import _REASSESS_TIMEOUT_SECS, _VERDICT_CONTRACT_TIMEOUT_SECS, _VERDICT_FENCE_RE, _VERDICT_REPAIR_TIMEOUT_SECS
from ._shared import _checkpoint_run


def _format_verdict_block(verdict: dict) -> str:
    """Render the canonical fenced JSON block appended to final reports."""
    return "```json\n" + json.dumps(verdict, indent=2, ensure_ascii=False) + "\n```"
def _strip_trailing_verdict_block(text: str) -> str:
    """Remove a trailing fenced verdict JSON block so the canonical one is unique."""
    current = (text or "").rstrip()
    while True:
        matches = list(_VERDICT_FENCE_RE.finditer(current))
        if not matches:
            return current
        last = matches[-1]
        if last.end() != len(current):
            return current
        try:
            obj = json.loads(last.group(1))
        except (json.JSONDecodeError, ValueError):
            return current
        if not isinstance(obj, dict) or "verdict" not in obj:
            return current
        current = current[:last.start()].rstrip()
def _attach_verdict_block(final_answer: str, verdict: dict) -> str:
    """Ensure the final answer ends with exactly one canonical verdict block."""
    base = _strip_trailing_verdict_block(final_answer)
    return base.rstrip() + ("\n\n" if base.strip() else "") + _format_verdict_block(verdict)
def _apply_verdict_policies(
    state: AgentState,
    verdict: dict,
    final_answer: str,
    *,
    normalize_followups: bool = False,
) -> dict:
    src = src_label(state["agent_name"])
    problems = validate_verdict(verdict)
    if problems:
        emit(src, "note", f"verdict validation: {'; '.join(problems)[:200]}")

    over_budget = (
        state.get("status") == "incomplete_budget"
        or state.get("steps", 0) >= state.get("max_steps", 0) > 0
        or state.get("tool_calls_made", 0) >= state.get("max_tool_calls", 0) > 0
    )
    verdict, notes = apply_verdict_integrity(
        verdict,
        strict=(state["agent_name"] == "triage"),
        escalation_posted=bool(state.get("escalation_posted")),
        over_budget=over_budget,
        classify_gaps=normalize_followups,
    )
    for kind, msg in notes:
        emit(src, kind, msg)
    if not notes:
        if verdict.get("nonblocking_gaps"):
            emit(src, "note",
                 f"verdict {verdict.get('verdict','').upper()} accepted with "
                 "nonblocking gaps")
        emit(src, "note",
             f"verdict: {verdict.get('verdict','').upper()} "
             f"({verdict.get('confidence','?')})")
    return verdict
async def finish(state: AgentState, config) -> dict:
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "finish", state)
    if state.get("status") == "cancelled":
        emit(src, "done", "cancelled")
        return {
            "status": "cancelled",
            "final_answer": state.get("final_answer") or f"{state['agent_name']} cancelled.",
        }

    tools = config["configurable"]["tools"]
    tmap = _tmap(tools)

    over_budget = (
        state["steps"] >= state["max_steps"]
        or state["tool_calls_made"] >= state["max_tool_calls"]
    )

    # If budget was exhausted while a task was in-progress, save whatever partial
    # work the model produced so it appears in the investigation summary.
    current_task = state.get("current_task")
    if over_budget and current_task and state["agent_name"] == "investigation":
        complete_fn = tmap.get("complete_task")
        if complete_fn:
            partial = ""
            for msg in reversed(state.get("messages", [])):
                content = getattr(msg, "content", "")
                if content and getattr(msg, "type", "") == "ai":
                    partial = content.strip()
                    break
            note = (
                "[Budget exhausted — partial findings]\n\n" + partial
                if partial else
                "[Budget exhausted — no findings recorded for this task]"
            )
            await _call(complete_fn, {"task_id": current_task["id"], "summary": note}, _dbg=src)
            emit(src, "note",
                 f"budget: saved partial work for "
                 f"'{(current_task.get('title') or current_task['id'])[:60]}'")

    # Build a structured investigation summary so the orchestrator and analyst
    # always receive complete findings, not just the last task's answer.
    if state["agent_name"] == "investigation":
        final_answer = await _build_investigation_summary(
            state, tmap, config["configurable"].get("model")
        )
    else:
        final_answer = state.get("final_answer") or f"{state['agent_name']} complete."

    status = "incomplete_budget" if over_budget else "completed"
    await _checkpoint_run(
        state["run_id"],
        status=status,
        result=final_answer,
        phase="finish",
    )
    emit(src, "done",
         f"{status} (steps={state['steps']}/{state['max_steps']}, "
         f"calls={state['tool_calls_made']}/{state['max_tool_calls']})")
    return {
        "status": status,
        "final_answer": final_answer,
        "verdict": None,
    }
async def verdict_contract(state: AgentState, config) -> dict:
    """Triage/investigation node that creates the canonical verdict contract.

    The final report narrative is useful to humans, but the structured verdict
    is a downstream control signal. Generate it in a focused tool-free call so
    open scoping gaps do not leak into `blocking_gaps` unless they truly block
    the TP/FP classification.
    """
    if state["agent_name"] not in {"triage", "investigation"}:
        return {}

    src = src_label(state["agent_name"])
    _emit_node_entry(src, "verdict_contract", state)

    final_answer = state.get("final_answer") or ""
    model = config["configurable"].get("model")

    if model is None:
        verdict = parse_verdict(final_answer)
        problems = validate_verdict(verdict) if verdict is not None else ["missing verdict"]
        if verdict is None or problems:
            emit(src, "error", f"missing valid {state['agent_name']} verdict contract and no model available")
            return {"status": "failed", "verdict": None, "final_answer": final_answer}
        verdict = _apply_verdict_policies(
            state, verdict, final_answer, normalize_followups=True
        )
        return {"verdict": verdict, "final_answer": _attach_verdict_block(final_answer, verdict)}

    system = (
        "You are a senior SOC verdict controller. Return ONLY a fenced JSON "
        "diagnosis verdict block. Do not write prose."
    )
    prompt = (
        f"Case: {state['case_id']}\n"
        f"Agent: {state['agent_name']}\n"
        f"Question: {state['question']}\n\n"
        "Use the agent report and structured findings below to generate "
        "the canonical verdict JSON contract. The contract is a control signal, "
        "not a narrative summary.\n\n"
        "Rules:\n"
        "- `tp` means the alert/detection is a true positive for its matched behavior, "
        "not necessarily that full host compromise is proven. If the case is a web-scan, "
        "brute-force, exploit-attempt, C2, persistence, or execution alert, raw telemetry "
        "that confirms that malicious/offensive behavior is sufficient for `tp` with "
        "`classification_basis=malicious_evidence`.\n"
        "- Do not demote a confirmed offensive alert to `needs_investigation` merely "
        "because downstream phases such as successful access, execution, persistence, "
        "callback, exfiltration, or impact remain unproven. Put those as "
        "`nonblocking_gaps` unless they contradict the alert's own matched behavior.\n"
        "- `fp` requires affirmative benign evidence.\n"
        "- Use `blocking_gaps` only for gaps that prevent TP/FP classification.\n"
        "- Missing initial-access source IP, missing network callback confirmation, "
        "incomplete cron execution count, missing analyst corrections, and incomplete "
        "campaign scope are `nonblocking_gaps` when direct malicious persistence or "
        "payload evidence already proves TP.\n"
        "- Confirmed syscheck/FIM evidence of a reverse-shell cron entry should be "
        "`tp` with `classification_basis=malicious_evidence`, `impact_state=active`, "
        "and `scope_state=isolated` unless lateral spread is proven.\n"
        "- For triage, `needs_investigation` is appropriate when the initial triage "
        "evidence is insufficient or conflicting. Only choose `tp` or `fp` when the "
        "triage report cites evidence that supports that classification.\n"
        "- Keep truly classification-blocking gaps in `blocking_gaps`, for example "
        "`cannot distinguish admin from attacker` or `persistence cannot be confirmed`.\n\n"
        "Return EXACTLY this fenced JSON block:\n"
        "```json\n"
        "{\n"
        '  "verdict": "tp | fp | inconclusive | needs_investigation",\n'
        '  "confidence": "low | medium | high",\n'
        '  "classification_basis": "malicious_evidence | benign_evidence | insufficient_evidence | conflicting_evidence",\n'
        '  "impact_state": "active | contained | unknown",\n'
        '  "scope_state": "isolated | lateral_spread | unknown",\n'
        '  "matched_patterns": [],\n'
        '  "supporting_evidence": ["<event ID / fact backing the verdict>"],\n'
        '  "contradicting_evidence": [],\n'
        '  "blocking_gaps": [],\n'
        '  "nonblocking_gaps": [],\n'
        '  "missing_evidence": [],\n'
        '  "recommended_action": ""\n'
        "}\n"
        "```\n\n"
        f"## Agent report and structured findings\n{final_answer}"
    )

    try:
        resp = await asyncio.wait_for(
            model.bind_tools([]).ainvoke([
                SystemMessage(content=system),
                HumanMessage(content=prompt),
            ]),
            timeout=_VERDICT_CONTRACT_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        contract_text = (getattr(resp, "content", "") or "").strip()
    except asyncio.TimeoutError:
        emit(src, "error", f"verdict contract timed out ({_VERDICT_CONTRACT_TIMEOUT_SECS}s)")
        return {"status": "failed", "verdict": None, "final_answer": final_answer}
    except Exception as exc:
        emit(src, "error", f"verdict contract failed ({exc})")
        return {"status": "failed", "verdict": None, "final_answer": final_answer}

    verdict = parse_verdict(contract_text)
    problems = validate_verdict(verdict) if verdict is not None else []
    if verdict is None or problems:
        repaired_answer, verdict, problems = await _repair_verdict_output(
            state,
            config,
            final_answer.rstrip() + "\n\n" + contract_text,
            verdict,
            problems,
        )
        if verdict is None or problems:
            emit(src, "error", "missing valid structured verdict after contract repair")
            return {
                "status": "failed",
                "final_answer": _strip_trailing_verdict_block(repaired_answer),
                "verdict": None,
            }

    verdict = _apply_verdict_policies(
        state, verdict, final_answer, normalize_followups=True
    )
    return {
        "verdict": verdict,
        "final_answer": _attach_verdict_block(final_answer, verdict),
    }
async def _repair_verdict_output(state: AgentState, config, final_answer: str, verdict, problems: list[str]) -> tuple[str, dict | None, list[str]]:
    """Attempt one text-only repair pass for a missing/invalid verdict contract."""
    src = src_label(state["agent_name"])
    model = config["configurable"].get("model")
    sys_prompt = config["configurable"].get("system_prompt", "")
    if model is None:
        if verdict is None:
            emit(src, "warning", "missing structured verdict and no model available for repair")
        else:
            emit(src, "warning", "invalid structured verdict and no model available for repair")
        return final_answer, verdict, problems
    issue = "missing structured verdict block" if verdict is None else f"invalid verdict block: {'; '.join(problems)}"
    emit(src, "warning", f"attempting verdict repair ({issue[:200]})")
    prompt = (
        "Your previous final answer did not produce a valid diagnosis verdict contract. "
        "Return ONLY one fenced JSON block that fixes the verdict and matches the required schema. "
        "Do not include any prose.\n\n"
        f"## Prior final answer\n{final_answer}\n\n"
        "Required schema:\n"
        "```json\n"
        "{\n"
        '  "verdict": "tp | fp | inconclusive | needs_investigation",\n'
        '  "confidence": "low | medium | high",\n'
        '  "classification_basis": "malicious_evidence | benign_evidence | insufficient_evidence | conflicting_evidence",\n'
        '  "impact_state": "active | contained | unknown",\n'
        '  "scope_state": "isolated | lateral_spread | unknown",\n'
        '  "matched_patterns": [],\n'
        '  "supporting_evidence": ["<event ID / fact backing the verdict>"],\n'
        '  "contradicting_evidence": [],\n'
        '  "blocking_gaps": [],\n'
        '  "nonblocking_gaps": [],\n'
        '  "missing_evidence": [],\n'
        '  "recommended_action": ""\n'
        "}\n"
        "```"
    )
    try:
        resp = await asyncio.wait_for(
            model.bind_tools([]).ainvoke([
                SystemMessage(content=sys_prompt),
                HumanMessage(content=prompt),
            ]),
            timeout=_VERDICT_REPAIR_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        repair_text = (getattr(resp, "content", "") or "").strip()
        repaired_answer = final_answer.rstrip() + ("\n\n" if final_answer.strip() else "") + repair_text
        repaired_verdict = parse_verdict(repaired_answer)
        repaired_problems = validate_verdict(repaired_verdict) if repaired_verdict is not None else []
        if repaired_verdict is not None and not repaired_problems:
            emit(src, "note", "verdict repair succeeded")
            return repaired_answer, repaired_verdict, repaired_problems
        emit(src, "warning", "verdict repair did not yield a valid contract")
        return repaired_answer, repaired_verdict, repaired_problems
    except asyncio.TimeoutError:
        emit(src, "warning", f"verdict repair timed out ({_VERDICT_REPAIR_TIMEOUT_SECS}s)")
        return final_answer, verdict, problems
    except Exception as exc:
        emit(src, "warning", f"verdict repair failed ({exc})")
        return final_answer, verdict, problems
async def reassess_verdict(state: AgentState, config) -> dict:
    """Post-finish node: compare synthesis verdict against triage verdict.

    No-op for triage runs, runs without a handoff verdict, or when triage and
    synthesis already agree (zero extra model calls in that case).

    When they conflict, fires one focused model call that sees the full
    investigation narrative and both verdicts, then overwrites state["verdict"]
    with the resolved result.  The resolved verdict always carries:
    - triage_verdict: what triage said (set whenever the node runs and finds a
      parseable triage verdict, even on agreement)
    - reassessment_reason: one-sentence explanation (set on conflict only)
    """
    if state["agent_name"] != "investigation":
        return {}

    src = src_label(state["agent_name"])
    _emit_node_entry(src, "reassess_verdict", state)

    synthesis_verdict = state.get("verdict")
    if not synthesis_verdict:
        return {}

    handoff = state.get("handoff") or {}
    triage_report = handoff.get("triage_report") or ""
    if not triage_report:
        return {}

    triage_verdict_dict = parse_verdict(triage_report)
    if not triage_verdict_dict:
        return {}

    triage_v = triage_verdict_dict.get("verdict")
    synthesis_v = synthesis_verdict.get("verdict")

    # No conflict — tag and return without an extra model call.
    if triage_v == synthesis_v:
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        emit(src, "note",
             f"reassess_verdict: triage and investigation agree ({(synthesis_v or '').upper()})")
        return {"verdict": updated}

    if (
        triage_v in {"needs_investigation", "inconclusive"}
        and synthesis_v in {"tp", "fp"}
        and synthesis_verdict.get("supporting_evidence")
        and not synthesis_verdict.get("blocking_gaps")
    ):
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        updated["reassessment_reason"] = (
            "Investigation produced a cited TP/FP verdict with no classification-blocking gaps."
        )
        emit(src, "note",
             f"reassess_verdict: accepted investigation {synthesis_v.upper()} "
             f"over triage {triage_v.upper()} without model call")
        return {"verdict": updated}

    # Conflict — one focused model call to resolve it.
    model = config["configurable"].get("model")
    if model is None:
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        emit(src, "note",
             f"reassess_verdict: conflict triage={triage_v} vs synthesis={synthesis_v} "
             "— no model available, keeping synthesis verdict")
        return {"verdict": updated}

    emit(src, "note",
         f"reassess_verdict: conflict triage={triage_v.upper()} vs "
         f"synthesis={synthesis_v.upper()} — resolving")

    final_answer = state.get("final_answer") or ""
    _NARRATIVE_LIMIT = 8000
    if len(final_answer) > _NARRATIVE_LIMIT:
        final_answer = (
            final_answer[:_NARRATIVE_LIMIT]
            + "\n\n[clipped — full narrative in final.md]"
        )

    def _vsummary(v: dict) -> str:
        return (
            f"verdict={v.get('verdict', '?').upper()}, "
            f"confidence={v.get('confidence', '?')}\n"
            f"classification_basis={v.get('classification_basis', '')}\n"
            f"supporting_evidence={v.get('supporting_evidence', [])}\n"
            f"blocking_gaps={v.get('blocking_gaps', [])}\n"
            f"nonblocking_gaps={v.get('nonblocking_gaps', [])}\n"
            f"missing_evidence={v.get('missing_evidence', [])}"
        )

    system = (
        "You are a senior SOC analyst performing a final verdict review. "
        "The triage and investigation synthesis verdicts conflict. "
        "Return ONLY the fenced JSON verdict block requested — no other text."
    )
    prompt = (
        f"## Triage verdict (before investigation)\n{_vsummary(triage_verdict_dict)}\n\n"
        f"## Investigation synthesis verdict (after investigation)\n{_vsummary(synthesis_verdict)}\n\n"
        f"## Full investigation narrative\n{final_answer}\n\n"
        "Based on the full investigation narrative, resolve the verdict conflict. "
        "Prefer the investigation verdict when its supporting_evidence is grounded "
        "in the narrative; prefer the triage verdict when the synthesis evidence "
        "list is empty or inconsistent with what the narrative says. Resolve `tp` "
        "relative to the alert's matched behavior: confirmed web scanning, brute force, "
        "exploit attempt, C2, persistence, or execution is a TP for that detection even "
        "when later compromise phases remain unproven. Treat those later-phase unknowns "
        "as nonblocking gaps unless they prevent classification of the alert behavior "
        "itself.\n\n"
        "Return EXACTLY this fenced JSON block — no other text:\n"
        "```json\n"
        "{\n"
        '  "verdict": "tp | fp | inconclusive | needs_investigation",\n'
        '  "confidence": "low | medium | high",\n'
        '  "classification_basis": "malicious_evidence | benign_evidence | insufficient_evidence | conflicting_evidence",\n'
        '  "impact_state": "active | contained | unknown",\n'
        '  "scope_state": "isolated | lateral_spread | unknown",\n'
        '  "matched_patterns": [],\n'
        '  "supporting_evidence": ["<evidence backing your verdict>"],\n'
        '  "contradicting_evidence": [],\n'
        '  "blocking_gaps": [],\n'
        '  "nonblocking_gaps": [],\n'
        '  "missing_evidence": [],\n'
        '  "recommended_action": "",\n'
        f'  "triage_verdict": "{triage_v}",\n'
        '  "reassessment_reason": "<one sentence: why you chose this verdict>"\n'
        "}\n"
        "```"
    )

    try:
        resp = await asyncio.wait_for(
            model.bind_tools([]).ainvoke([
                SystemMessage(content=system),
                HumanMessage(content=prompt),
            ]),
            timeout=_REASSESS_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        text = (getattr(resp, "content", "") or "").strip()
        resolved = parse_verdict(text)
        if resolved:
            if "triage_verdict" not in resolved:
                resolved["triage_verdict"] = triage_v
            emit(src, "note",
                 f"reassess_verdict: resolved to {resolved.get('verdict', '?').upper()} "
                 f"(triage={triage_v.upper()}, synthesis={synthesis_v.upper()}); "
                 f"reason={resolved.get('reassessment_reason', '—')}")
            return {"verdict": resolved}
        # Unparseable — fall back to synthesis with triage tag
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        emit(src, "warning",
             "reassess_verdict: model returned unparseable response — keeping synthesis verdict")
        return {"verdict": updated}

    except asyncio.TimeoutError:
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        emit(src, "warning",
             f"reassess_verdict: timed out ({_REASSESS_TIMEOUT_SECS}s) — keeping synthesis verdict")
        return {"verdict": updated}
    except Exception as exc:
        updated = dict(synthesis_verdict)
        updated["triage_verdict"] = triage_v
        emit(src, "warning",
             f"reassess_verdict: error — keeping synthesis verdict ({exc})")
        return {"verdict": updated}
def _build_session_note(state: AgentState, verdict: dict | None, final_answer: str) -> str:
    return _build_publication_session_note(state, verdict, final_answer)
async def publish_finish(state: AgentState, config) -> dict:
    """Publish the final investigation report after verdict reassessment."""
    if state["agent_name"] != "investigation":
        return {}
    if state.get("status") == "failed":
        return {}

    src = src_label(state["agent_name"])
    _emit_node_entry(src, "publish_finish", state)
    tools = config["configurable"]["tools"]
    tmap = _tmap(tools)
    final_answer = state.get("final_answer") or ""
    verdict = state.get("verdict")
    # Defensive re-application of the verdict-integrity pipeline: reassess_verdict may
    # have overwritten the synthesis verdict via its conflict-resolution model call,
    # which bypasses the pipeline entirely. Re-run it here — the last node before END —
    # so an escalated / budget-truncated / unverified-benign verdict never publishes.
    # Idempotent: a verdict already floored is unchanged.
    floored_verdict_update: dict | None = None
    if verdict:
        over_budget = (
            state.get("status") == "incomplete_budget"
            or state.get("steps", 0) >= state.get("max_steps", 0) > 0
            or state.get("tool_calls_made", 0) >= state.get("max_tool_calls", 0) > 0
        )
        verdict, notes = apply_verdict_integrity(
            verdict,
            strict=(state["agent_name"] == "triage"),
            escalation_posted=bool(state.get("escalation_posted")),
            over_budget=over_budget,
        )
        if notes:
            floored_verdict_update = verdict
            for _kind, _msg in notes:
                emit(src, "note", f"publish_finish: {_msg}")
        final_answer = _attach_verdict_block(final_answer, verdict)

    write_fn = tmap.get("write")
    if write_fn:
        path = f"{reports_dir(state['case_id'])}/final.md"

        async def call_tool(name: str, args: dict) -> str:
            fn = tmap.get(name)
            if fn is None:
                return f"Error: tool '{name}' is not available"
            return await _call(fn, args)

        await write_file(
            call_tool=call_tool,
            path=path,
            content=final_answer,
            created_by=state["agent_name"],
            summary="Final investigation report.",
        )

        # Session handoff note (AVFS `/sessions`): lets the next run resume per the
        # AVFS prompt's "read /sessions first" guidance instead of re-deriving context.
        try:
            note_path = session_note_path(state["run_id"])
            await write_file(
                call_tool=call_tool,
                path=note_path,
                content=_build_session_note(state, verdict, final_answer),
                created_by=state["agent_name"],
                summary=f"Session handoff for case {state['case_id']}.",
            )
            emit(src, "note", f"workspace: wrote session handoff note {note_path}")
        except Exception as exc:
            emit(src, "warning", "session handoff note write failed", detail=str(exc))

    result: dict = {"final_answer": final_answer}
    if floored_verdict_update is not None:
        result["verdict"] = floored_verdict_update
    await _checkpoint_run(
        state["run_id"],
        status=state.get("status"),
        result=final_answer,
        verdict=(floored_verdict_update if floored_verdict_update is not None else verdict),
        phase="publish_finish",
    )
    return result
