from __future__ import annotations

import asyncio
import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ...workspace.avfs_writer import write_file
from ..analysis.verdict import (
    apply_citation_policy,
    apply_open_gaps_policy,
    normalize_followup_gaps,
    parse_verdict,
    validate_verdict,
)
from ..infra.avfs import reports_dir
from ..infra.logbus import emit, src_label

from .board import _record_board_entry, _record_hypotheses_text
from .lead_model import validate_leads_model
from .parsing import _CONFIRMED_FACTS_RE, _EVENT_ID_DUMP_RE, _FACT_BULLET_RE, _HYPOTHESES_RE, _NEW_LEADS_HEADER_RE, _extract_report_section, _extract_source_refs, _is_none_bullet, _missing_summary_sections, _normalize_fact_key, _section_body, _section_has_concrete_items, _strip_markers
from .sanitize import _sanitize_history, _sanitize_message
from .state import AgentState
from .synthesis import _build_investigation_summary, _execution_record
from .toolio import _SEED_TASK_TITLE, _call, _emit_node_entry, _extract_input_tokens, _is_error_tool_result, _list_tasks, _tmap
from .validation import _collect_escalation_facts

log = logging.getLogger(__name__)





# Cap on follow-up tasks the pivot node may auto-create across a single run.
# Without this, each completed task can spawn new "## New Leads" tasks that spawn
# more, so the queue never drains and the run only ends by exhausting its step
# budget (status=incomplete_budget) rather than reaching a verdict. Initial tasks
# seeded from the triage plan are NOT counted — only leads discovered mid-run.
# Past the cap, surplus leads are still surfaced as open leads on the Findings
# Board (and in the final report); they are simply not auto-enqueued.
_MAX_PIVOT_TASKS = 10
_VERDICT_REPAIR_TIMEOUT_SECS = 45

# How many times the assess node will nudge an investigation task to re-emit a
# malformed report before accepting the best-effort answer so the run never
# stalls on a model that cannot produce the required four-section format.
_MAX_SUMMARY_FORMAT_RETRIES = 2

_TRIAGE_SIEM_TOOLS = frozenset({
    "search_keyword",
    "search",
    "profile_field",
})

# Keywords that signal a task explicitly requires SIEM event queries.
# Used by the investigation SIEM guard to avoid applying the guard to
# administrative or SOAR-only tasks (reporting, case comments, etc.).
_INVESTIGATION_SIEM_KEYWORDS = (
    "siem",
    "pivot to",
    "events from",
    "events to",
    "search events",
    "siem event",
    "48-hour",
    "24-hour",
    "time window",
    "surrounding the alert",
    "connection evidence",
    "ssh evidence",
    "http evidence",
    "all events",
)

_VERDICT_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_PLAN_ITEM_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(.+)$", re.MULTILINE)


def _has_tool_message(messages: list, names: set[str] | frozenset[str]) -> bool:
    return any(getattr(msg, "name", "") in names for msg in messages)


def _task_requires_siem(task: dict) -> bool:
    """Return True if the task title/description signals that SIEM queries are required."""
    combined = (
        (task.get("title") or "") + " " + (task.get("description") or "")
    ).lower()
    return any(kw in combined for kw in _INVESTIGATION_SIEM_KEYWORDS)


def _format_verdict_block(verdict: dict) -> str:
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
    base = _strip_trailing_verdict_block(final_answer)
    return base.rstrip() + ("\n\n" if base.strip() else "") + _format_verdict_block(verdict)


def _expected_seed_task_count(seed_description: str) -> int:
    """Count planned investigation items embedded in the seed-task handoff text."""
    triage_report = (seed_description or "").split("## Triage report", 1)
    if len(triage_report) == 2:
        triage_report = triage_report[1]
    else:
        triage_report = seed_description or ""

    leads_section = _extract_report_section(triage_report, "New Leads")
    if leads_section.strip():
        bullets = [m.group(1).strip() for m in _PLAN_ITEM_RE.finditer(leads_section) if not _is_none_bullet(m.group(1))]
        if bullets:
            return len(bullets)

    plan_section = _extract_report_section(triage_report, "Investigation Plan")
    if plan_section.strip():
        bullets = [m.group(1).strip() for m in _PLAN_ITEM_RE.finditer(plan_section) if not _is_none_bullet(m.group(1))]
        if bullets:
            return len(bullets)
    return 0


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

    any_demoted = False
    verdict, demoted = apply_citation_policy(verdict)
    if demoted:
        any_demoted = True
        emit(src, "note",
             f"verdict {verdict.get('demoted_from','').upper()} demoted to "
             "INCONCLUSIVE — no supporting evidence cited")

    if (
        state["agent_name"] == "triage"
        and verdict.get("verdict") in ("tp", "fp")
        and not verdict.get("missing_evidence")
        and _section_has_concrete_items(_extract_report_section(final_answer, "Evidence Gaps"))
    ):
        verdict = dict(verdict)
        verdict["missing_evidence"] = ["Evidence gaps listed in report but omitted from verdict JSON."]

    if normalize_followups:
        normalized = normalize_followup_gaps(verdict)
        if normalized is not verdict and normalized.get("blocking_gaps") != verdict.get("blocking_gaps"):
            emit(src, "note", "verdict contract: moved follow-up gaps to nonblocking_gaps")
        verdict = normalized

    verdict, demoted = apply_open_gaps_policy(verdict, strict=(state["agent_name"] == "triage"))
    if demoted:
        any_demoted = True
        reason = "blocking gaps" if verdict.get("blocking_gaps") else "classification basis"
        emit(src, "note",
             f"verdict {verdict.get('demoted_from','').upper()} demoted to "
             f"NEEDS_INVESTIGATION — {reason}")
    if not any_demoted:
        if verdict.get("nonblocking_gaps"):
            emit(src, "note",
                 f"verdict {verdict.get('verdict','').upper()} accepted with "
                 "nonblocking gaps")
        emit(src, "note",
             f"verdict: {verdict.get('verdict','').upper()} "
             f"({verdict.get('confidence','?')})")
    return verdict



async def assess(state: AgentState, config) -> dict:
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
                synth_msgs = _sanitize_history(
                    state["messages"] + [HumanMessage(content=(
                        "Based on the tool results above, write your complete analysis "
                        "and findings as text now. Do not make any further tool calls."
                    ))]
                )
                synth_resp = await text_only.ainvoke([SystemMessage(content=sys_prompt)] + synth_msgs)
                _sanitize_message(synth_resp)
                final_answer = (synth_resp.content or "").strip()
                new_ctx = _extract_input_tokens(synth_resp) or new_ctx
            except Exception as exc:
                log.warning("[%s] assess synthesis failed: %s", state["agent_name"], exc)
        if not final_answer:
            final_answer = _execution_record(state["messages"])

    # Seed guard: if the investigation seed task completed without creating any
    # investigation tasks, re-inject a correction and route back to think so the
    # model gets another chance to populate the queue before the run finishes.
    if (
        state["agent_name"] == "investigation"
        and task
        and _SEED_TASK_TITLE in (task.get("title") or "").lower()
    ):
        tasks = await _list_tasks(tools, state["case_id"], state["run_id"], state["agent_name"])
        seeded = [
            t for t in tasks
            if _SEED_TASK_TITLE not in (t.get("title") or "").lower()
        ]
        expected = _expected_seed_task_count(task.get("description") or "")
        if len(seeded) < max(1, expected):
            emit(src, "note",
                 "seed guard: seed task completed before populating full investigation queue — re-injecting correction")
            remaining = max(1, expected) - len(seeded)
            correction = HumanMessage(content=(
                f"You have created {len(seeded)} investigation task(s), but at least {max(1, expected)} "
                f"are required from the triage handoff. {remaining} more task(s) must still be created. "
                "Your ONLY goal for this task is to call `create_task` for every numbered "
                "or bulleted item in the triage investigation plan / New Leads section. "
                "Do not write a summary until all required tasks are created. "
                "Please call `create_task` now for the missing task(s)."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "seed_guard",
                "ctx_tokens": new_ctx,
            }

    if state["agent_name"] == "triage" and task:
        available_siem_tools = set(_tmap(tools)) & _TRIAGE_SIEM_TOOLS
        if available_siem_tools and not _has_tool_message(state["messages"], available_siem_tools):
            emit(
                src,
                "note",
                "triage SIEM guard: task completed without nearby SIEM events query — re-injecting correction",
            )
            tool_list = ", ".join(sorted(available_siem_tools))
            correction = HumanMessage(content=(
                "You finished the triage report without loading other alerts/events close "
                "to the current case or alert timestamp. Before writing the final report, "
                "use the SIEM now. Derive an absolute time window around the linked alert "
                "timestamp and call one of these available tools: "
                f"{tool_list}. Query nearby events for the same host, user, source IP, "
                "rule family, command, or file path. Then revise the report to include "
                "what nearby events were found, or state the exact zero-result SIEM query."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "triage_siem_guard",
                "ctx_tokens": new_ctx,
            }

    # Investigation SIEM guard: tasks that explicitly target SIEM event pivots
    # (identified by keywords in the title/description) must call at least one
    # SIEM tool before completing. Mirrors the triage SIEM guard above.
    if (
        state["agent_name"] == "investigation"
        and task
        and _SEED_TASK_TITLE not in (task.get("title") or "").lower()
        and _task_requires_siem(task)
    ):
        available_siem_tools = set(_tmap(tools)) & _TRIAGE_SIEM_TOOLS
        if available_siem_tools and not _has_tool_message(state["messages"], available_siem_tools):
            emit(
                src,
                "note",
                "investigation SIEM guard: SIEM-pivot task completed without a SIEM query — re-injecting correction",
            )
            tool_list = ", ".join(sorted(available_siem_tools))
            correction = HumanMessage(content=(
                "You completed this investigation task without querying the SIEM, but the "
                "task explicitly requires SIEM event data. Use one of these tools now: "
                f"{tool_list}. "
                "Search for events related to the task's target (IP address, user, host, "
                "hash, or command) in the time window specified. A zero-result query is a "
                "valid confirmed negative — record it and revise your answer to include the "
                "exact query and its result. Do not write a final answer until you have "
                "made at least one SIEM query."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "investigation_siem_guard",
                "ctx_tokens": new_ctx,
            }

    # Summary-format guard: the per-task report is the only place grounded
    # findings are recorded (the board is built by extracting its Confirmed Facts
    # section), so a malformed report silently loses evidence — e.g. a reverse
    # shell seen in a SIEM result that never made it into a section. Validate the
    # report shape syntactically and nudge the model to re-emit, with full tool
    # context still in scope, before completing the task.
    if (
        state["agent_name"] == "investigation"
        and task
        and _SEED_TASK_TITLE not in (task.get("title") or "").lower()
    ):
        missing = _missing_summary_sections(final_answer)
        retries = state.get("summary_format_retries", 0) or 0
        if missing and retries < _MAX_SUMMARY_FORMAT_RETRIES:
            emit(src, "note",
                 f"summary format guard: missing/empty section(s) {', '.join(missing)} "
                 f"— re-injecting correction (retry {retries + 1}/{_MAX_SUMMARY_FORMAT_RETRIES})")
            correction = HumanMessage(content=(
                "Your report is missing or has an empty required section: "
                f"{', '.join(missing)}. Re-emit the COMPLETE report now using the "
                "mandatory four-section format:\n\n"
                "## Confirmed Facts\n## Findings\n## Hypotheses\n## New Leads\n\n"
                "Populate every section from the tool results above. Put each "
                "confirmed indicator you observed in tool output — including any "
                "reverse shell, C2/callback, or command-execution evidence — under "
                "## Confirmed Facts with its event ID. Use '- None.' only for a "
                "section that is genuinely empty. Do not make further tool calls."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "summary_format_guard",
                "summary_format_retries": retries + 1,
                "ctx_tokens": new_ctx,
            }
        if missing:
            emit(src, "warning",
                 f"summary format guard: accepting best-effort report after "
                 f"{retries} retries; still missing section(s) {', '.join(missing)}")

    if complete_fn and task:
        await _call(complete_fn, {"task_id": task["id"], "summary": final_answer}, _dbg=src)
        emit(src, "note",
             f"completed '{task.get('title', task['id'])}' "
             f"(steps={state['steps']}, calls={state['tool_calls_made']})",
             detail=final_answer)
    return {
        "current_task": None,
        "last_completed_task": task,
        "messages": [],
        "final_answer": final_answer,
        "ctx_tokens": new_ctx,
        "status": "",
        "summary_format_retries": 0,
    }


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
        escalation_facts = _collect_escalation_facts(final_answer)
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

    # Push confirmed facts from "## Confirmed Facts" section to the board.
    # Accept ## / ### / **Confirmed Facts** variants (small models vary in heading level).
    # Recorded via the store path (not the add_fact MCP tool) so we can attach the
    # cited event ids/timestamps as `source` and dedup on a volatility-stripped key.
    _cf_match = _CONFIRMED_FACTS_RE.search(final_answer) if final_answer else None
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

    # Bound total follow-up tasks created across the run so the queue can drain and
    # the investigation converges to a verdict instead of exhausting its budget.
    already_created = state.get("pivot_tasks_created", 0) or 0
    remaining = max(0, _MAX_PIVOT_TASKS - already_created)
    completed_task = state.get("last_completed_task") or state.get("current_task")
    completed_task_id = (completed_task or {}).get("id")
    dedup_tasks = [
        t for t in tasks
        if t.get("id") != completed_task_id
        and _SEED_TASK_TITLE not in (t.get("title") or "").lower()
    ]
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
        remaining_run_budget=remaining,
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
    deferred: list[str] = []
    preserve_deferred = remaining < 3
    for decision in validation.deferred:
        candidate = decision.candidate
        if preserve_deferred:
            deferred.append(candidate.title)
            _record_board_entry(
                state,
                kind="hypothesis",
                content=f"Open lead (deferred — investigation lead budget reached): {candidate.title}",
                source="; ".join(filter(None, [candidate.pivots, candidate.evidence])),
                confidence="low",
                status="open",
                dedup_key=_normalize_fact_key(candidate.title),
            )
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
    if deferred:
        emit(src, "note",
             f"pivot: lead budget reached ({_MAX_PIVOT_TASKS}); deferred "
             f"{len(deferred)} lead(s) to open leads: {', '.join(deferred)[:200]}")
    return {
        "pivot_tasks_created": already_created + created,
        "escalation_posted": escalation_posted,
    }


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
    emit(src, "done",
         f"{status} (steps={state['steps']}/{state['max_steps']}, "
         f"calls={state['tool_calls_made']}/{state['max_tool_calls']})")
    return {
        "status": status,
        "final_answer": final_answer,
        "verdict": None,
    }


_VERDICT_CONTRACT_TIMEOUT_SECS = 90


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
        "- `tp` requires credible malicious evidence such as confirmed payload, "
        "unauthorized access, persistence, or execution.\n"
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


_REASSESS_TIMEOUT_SECS = 60


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
        "list is empty or inconsistent with what the narrative says.\n\n"
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
    if verdict:
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

    post_report_fn = tmap.get("post_case_report")
    if post_report_fn:
        import datetime
        date_str = datetime.date.today().isoformat()
        report_title = f"Investigation Report — {state['case_id']} — {date_str}"
        post_result = await _call(post_report_fn, {
            "case_id": state["case_id"],
            "summary": final_answer,
            "title": report_title,
        }, _dbg=src)
        if _is_error_tool_result(post_result):
            emit(src, "warning", "post_case_report failed", detail=post_result)
        else:
            emit(src, "note", "investigation report posted to case system")

    return {"final_answer": final_answer}
