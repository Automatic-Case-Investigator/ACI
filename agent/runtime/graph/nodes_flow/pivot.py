"""The `pivot` node: push confirmed findings to the board and queue validated follow-up leads."""
from __future__ import annotations

from ...infra.logbus import emit, src_label
from ..board import _record_board_entry, _record_hypotheses_text
from ..findings_model import FindingsVerification
from ..lead_model import validate_leads_model
from ..parsing import _EVENT_ID_DUMP_RE, _FACT_BULLET_RE, _FINDINGS_RE, _HYPOTHESES_RE, _NEW_LEADS_HEADER_RE, _extract_source_refs, _is_none_bullet, _normalize_fact_key, _section_body, _strip_markers
from ..state import AgentState
from ..toolio import _SEED_TASK_TITLE, _call, _emit_node_entry, _is_error_tool_result, _tmap
from ..validation import _board_compromise_facts, _collect_escalation_facts
import json

from ._const import _MAX_PIVOT_TASKS
from ._shared import _coerce_preserved_findings, _finding_bullet


async def pivot(state: AgentState, config) -> dict:
    """After each task: update the Findings Board, parse new leads,
    and create follow-up tasks. No model call — purely structural.
    """
    if state["agent_name"] != "investigation":
        return {}

    tools = config["configurable"]["tools"]
    tmap = _tmap(tools)
    final_answer = state.get("final_answer", "")
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "pivot", state)
    escalation_posted = state.get("escalation_posted", False)

    # Auto-escalation: if a task confirms active compromise with a cited event ID,
    # post an immediate comment so the analyst sees it before the final report.
    # Only fire once per run to avoid duplicate escalation noise.
    if not escalation_posted:
        # Read compromise evidence from the agent's narrative AND from the board's own
        # decoded artifacts (the authoritative source): a decoded reverse shell the decode
        # layer extracted must escalate even if the agent never wrote it into ## Findings.
        escalation_facts = _collect_escalation_facts(final_answer)
        _board_facts = _board_compromise_facts(state)
        _narrative = " ".join(escalation_facts).lower()
        for bf in _board_facts:
            if bf.lower() not in _narrative:
                escalation_facts.append(bf)
        if escalation_facts:
            comment_fn = tmap.get("post_case_comment")
            if comment_fn:
                fact_lines = "\n".join(f"- {f}" for f in escalation_facts)
                message = (
                    "⚠ **ACI ESCALATION ALERT** — Active compromise confirmed.\n\n"
                    f"**Case:** {state['case_id']}\n\n"
                    f"**Confirmed indicators (raw-evidence backed):**\n{fact_lines}\n\n"
                    "Immediate analyst review required. Full investigation report to follow."
                )
                result = await _call(comment_fn, {
                    "case_id": state["case_id"],
                    "message": message,
                }, _dbg=src)
                if not _is_error_tool_result(result):
                    emit(src, "note", "auto-escalation: active compromise alert posted to case")
                    escalation_posted = True
                else:
                    emit(src, "warning", "auto-escalation: post_case_comment failed", detail=result)

    # Push confirmed facts from the "## Findings" section to the board. Findings is
    # now the per-task system of record for grounded evidence; each bullet (with its
    # event id/timestamp) is a confirmed fact. Accept ## / ### / **Findings** variants
    # (small models vary in heading level). Narrative lines (no leading "- ") are
    # ignored. Recorded via the store path (not the add_fact MCP tool) so we can
    # attach the cited event ids/timestamps as `source` and dedup on a
    # volatility-stripped key.
    # Board-quality gating: only bullets the verifier classified `confirmed` become
    # board facts; restated/speculative/ungrounded bullets are dropped with a logged
    # reason. When verification is absent (fail-open path / non-SIEM task), fall back to
    # today's behavior — record every real (non-None) bullet.
    _verification = FindingsVerification.from_state(state.get("last_findings_verification"))
    _confirmed_keys: set[str] | None = None
    if _verification is not None:
        _confirmed_keys = {_normalize_fact_key(v.text) for v in _verification.verified if v.text}
        for v in _verification.rejected:
            emit(src, "note", f"findings board: dropped {v.status or 'unverified'} bullet")
    preserved_keys: set[str] = set()
    for finding in _coerce_preserved_findings(state.get("last_confirmed_findings")):
        content = _finding_bullet(finding)[2:].strip()
        key = _normalize_fact_key(content)
        if not key or key in preserved_keys:
            continue
        preserved_keys.add(key)
        _record_board_entry(
            state,
            kind="fact",
            content=content,
            source=finding.get("source") or _extract_source_refs(content),
            confidence="high",
            status="confirmed",
            dedup_key=key,
        )
        emit(src, "note", "findings board: preserved fact added")
    _cf_match = _FINDINGS_RE.search(final_answer) if final_answer else None
    if _cf_match:
        facts_block = _section_body(final_answer, _cf_match)
        for m in _FACT_BULLET_RE.finditer(facts_block):
            content, _ = _strip_markers(m.group(1).strip())
            if not content or _is_none_bullet(content):
                continue
            # Skip dangling lead-ins ("...appended:") and bare provenance dumps
            # ("Event IDs: a, b, c") — these are not findings.
            if content.rstrip().endswith(":") or _EVENT_ID_DUMP_RE.match(content):
                continue
            if _normalize_fact_key(content) in preserved_keys:
                continue
            # Gate to verifier-confirmed bullets when verification is available.
            if _confirmed_keys is not None and _normalize_fact_key(content) not in _confirmed_keys:
                continue
            _record_board_entry(
                state,
                kind="fact",
                content=content,
                source=_extract_source_refs(content),
                confidence="high",
                status="confirmed",
                dedup_key=_normalize_fact_key(content),
            )
            emit(src, "note", "findings board: fact added")

    # Hypotheses are structural output, so persist them deterministically even if
    # the model does not choose the add_hypothesis tool.
    _hyp_match = _HYPOTHESES_RE.search(final_answer) if final_answer else None
    if _hyp_match:
        created_hypotheses = _record_hypotheses_text(state, final_answer)
        for _ in range(created_hypotheses):
            emit(src, "note", "findings board: hypothesis added")

    _nl_match = _NEW_LEADS_HEADER_RE.search(final_answer) if final_answer else None
    if not _nl_match:
        return {}

    leads_section = _section_body(final_answer, _nl_match)
    if not leads_section.strip():
        return {}
    # Honor the analyst's "no leads" sentinel: when every bullet in the section is
    # a placeholder ("- None."), there are no leads to validate. Returning here
    # prevents the validator from inventing leads when the model explicitly
    # declared none — lead generation is the model's job (see §5/§6 pivot guide).
    lead_bullets = [
        _strip_markers(m.group(1).strip())[0]
        for m in _FACT_BULLET_RE.finditer(leads_section)
    ]
    if lead_bullets and all(_is_none_bullet(b) for b in lead_bullets):
        return {}

    list_fn = tmap.get("list_tasks")

    tasks: list[dict] = []
    if list_fn:
        raw = await _call(list_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
        })
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            tasks = data if isinstance(data, list) else data.get("tasks", [])
        except Exception:
            tasks = []

    src = src_label(state["agent_name"])

    already_created = state.get("pivot_tasks_created", 0) or 0

    # Convergence cap: stop creating tasks once the limit is reached so the
    # queue drains to empty and the investigation finishes cleanly.
    if already_created >= _MAX_PIVOT_TASKS:
        emit(src, "note",
             f"pivot: convergence cap reached ({already_created}/{_MAX_PIVOT_TASKS}) "
             f"— no further tasks created; queue will drain to finish")
        return {"escalation_posted": escalation_posted}

    completed_task = state.get("last_completed_task") or state.get("current_task")
    completed_task_id = (completed_task or {}).get("id")
    dedup_tasks = [
        t for t in tasks
        if t.get("id") != completed_task_id
        and _SEED_TASK_TITLE not in (t.get("title") or "").lower()
    ]
    # Augment with previously completed tasks not returned by list_tasks (queue
    # removes them on completion).  Passed as synthetic "completed" entries so
    # the lead validator's _task_blocks_duplicate logic applies correctly —
    # conclusive outcomes suppress re-investigation; inconclusive ones allow it.
    for ct in (state.get("completed_task_titles") or []):
        title = ct.get("title", "")
        if title and not any(t.get("title") == title for t in dedup_tasks):
            dedup_tasks.append({
                "title": title,
                "description": "",
                "summary": ct.get("summary", ""),
                "status": "completed",
            })
    # Model-based extraction + validation: the model reassembles inconsistently
    # formatted leads into whole candidates (avoiding the regex fragmentation that
    # split one lead into several invalid ones) and judges relevance/duplication;
    # the budget cap below stays deterministic.
    validation = await validate_leads_model(
        config["configurable"].get("model"),
        leads_section=leads_section,
        final_answer=final_answer,
        existing_tasks=dedup_tasks,
        current_task=completed_task,
        remaining_run_budget=None,
        agent_name=state["agent_name"],
    )
    counts = validation.counts()
    emit(
        src,
        "note",
        "lead validator: "
        f"approved={counts.get('approved', 0)} duplicate={counts.get('duplicate', 0)} "
        f"invalid={counts.get('invalid', 0)} low_relevance={counts.get('low_relevance', 0)} "
        f"over_cap={counts.get('over_cap', 0)}",
        detail=validation.detail(),
    )

    create_fn = tmap.get("create_task")
    if not create_fn:
        return {"escalation_posted": escalation_posted}

    created = 0
    for decision in validation.approved:
        candidate = decision.candidate
        result = await _call(create_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
            "title": candidate.title,
            "description": (
                f"Pivots: {candidate.pivots}\n"
                f"Evidence: {candidate.evidence}\n"
                f"Validator: {decision.reason}; signature={decision.signature}"
            ),
            "priority": candidate.priority,
        }, _dbg=src)
        if not _is_error_tool_result(result):
            created += 1
            emit(src, "note", f"pivot: created '{candidate.title}' (P{candidate.priority})")
        else:
            emit(src, "error", f"pivot: create_task failed for '{candidate.title}'", detail=result)

    if created:
        emit(src, "note", f"pivot: {created} follow-up task(s) queued")
    return {
        "pivot_tasks_created": already_created + created,
        "escalation_posted": escalation_posted,
    }
