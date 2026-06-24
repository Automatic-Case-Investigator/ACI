from __future__ import annotations

import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ...workspace.avfs_writer import write_file
from ..analysis.verdict import apply_citation_policy, apply_open_gaps_policy, parse_verdict, validate_verdict
from ..infra.avfs import reports_dir
from ..infra.logbus import emit, src_label

from .board import _record_board_entry, _record_hypotheses_text
from .parsing import _CONFIRMED_FACTS_RE, _EVENT_ID_DUMP_RE, _FACT_BULLET_RE, _HYPOTHESES_RE, _NEW_LEADS_HEADER_RE, _NEW_LEADS_RE, _extract_report_section, _extract_source_refs, _is_none_bullet, _normalize_fact_key, _section_body, _section_has_concrete_items, _strip_markers
from .sanitize import _sanitize_history, _sanitize_message
from .state import AgentState
from .synthesis import _build_investigation_summary, _execution_record
from .toolio import _SEED_TASK_TITLE, _call, _emit_node_entry, _extract_input_tokens, _has_pending_tasks, _is_error_tool_result, _tmap
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
        pending = await _has_pending_tasks(
            tools, state["case_id"], state["run_id"], state["agent_name"]
        )
        if not pending:
            emit(src, "note",
                 "seed guard: seed task completed without creating investigation tasks — re-injecting correction")
            correction = HumanMessage(content=(
                "You finished without calling `create_task`. "
                "Your ONLY goal for this task is to call `create_task` for every numbered "
                "item in the triage investigation plan. Do not write a summary until all "
                "tasks are created. Please call `create_task` now for each plan item."
            ))
            return {
                "current_task": task,
                "messages": list(state["messages"]) + [correction],
                "status": "seed_guard",
                "ctx_tokens": new_ctx,
            }

    if complete_fn and task:
        await _call(complete_fn, {"task_id": task["id"], "summary": final_answer}, _dbg=src)
        emit(src, "note",
             f"completed '{task.get('title', task['id'])}' "
             f"(steps={state['steps']}, calls={state['tool_calls_made']})",
             detail=final_answer)
    return {
        "current_task": None,
        "messages": [],
        "final_answer": final_answer,
        "ctx_tokens": new_ctx,
        "status": "",
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
    leads = _NEW_LEADS_RE.findall(leads_section)
    emit(src, "note", f"pivot: parsed {len(leads)} lead(s) from New Leads section")
    if not leads:
        return {}

    create_fn = tmap.get("create_task")
    list_fn = tmap.get("list_tasks")
    if not create_fn:
        return {}

    existing_titles: set[str] = set()
    if list_fn:
        raw = await _call(list_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
        })
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            tasks = data if isinstance(data, list) else data.get("tasks", [])
            existing_titles = {(t.get("title") or "").lower() for t in tasks}
        except Exception:
            pass

    src = src_label(state["agent_name"])

    # Bound total follow-up tasks created across the run so the queue can drain and
    # the investigation converges to a verdict instead of exhausting its budget.
    already_created = state.get("pivot_tasks_created", 0) or 0
    remaining = _MAX_PIVOT_TASKS - already_created

    def _lead_priority(p: str) -> int:
        try:
            return int(p)
        except (TypeError, ValueError):
            return 50

    # Highest-priority leads first, so when the cap is hit we keep the most
    # important threads and defer the rest.
    leads = sorted(leads, key=lambda lead: _lead_priority(lead[2]), reverse=True)

    created = 0
    deferred: list[str] = []
    for title, pivots, priority_str in leads:
        title = title.strip()
        if title.lower() in existing_titles:
            emit(src, "note", f"pivot: skipping duplicate '{title}'")
            continue
        if created >= remaining:
            # Lead budget reached — surface as an open lead on the board (so it
            # appears in the final report) instead of auto-enqueuing another task.
            deferred.append(title)
            existing_titles.add(title.lower())
            _record_board_entry(
                state,
                kind="hypothesis",
                content=f"Open lead (deferred — investigation lead budget reached): {title}",
                source=pivots.strip(),
                confidence="low",
                status="open",
                dedup_key=_normalize_fact_key(title),
            )
            continue
        result = await _call(create_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
            "title": title,
            "description": f"Pivots: {pivots.strip()}",
            "priority": _lead_priority(priority_str),
        }, _dbg=src)
        if not _is_error_tool_result(result):
            existing_titles.add(title.lower())
            created += 1
            emit(src, "note", f"pivot: created '{title}' (P{priority_str})")
        else:
            emit(src, "error", f"pivot: create_task failed for '{title}'", detail=result)

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

    write_fn = tmap.get("write")
    if write_fn and state["agent_name"] != "triage":
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

    # Post the compiled report to the case system so it appears in TheHive
    # regardless of whether the model called post_case_report during task execution.
    post_report_fn = tmap.get("post_case_report")
    if post_report_fn and state["agent_name"] == "investigation":
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

    # Parse the structured diagnosis verdict from the final answer and enforce the
    # citation policy: an uncited tp/fp is demoted to inconclusive so the system
    # never asserts a malicious/benign call it cannot back with evidence.
    verdict = parse_verdict(final_answer)
    if verdict is not None:
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
        verdict, demoted = apply_open_gaps_policy(verdict, strict=(state["agent_name"] == "triage"))
        if demoted:
            any_demoted = True
            emit(src, "note",
                 f"verdict {verdict.get('demoted_from','').upper()} demoted to "
                 "NEEDS_INVESTIGATION — open evidence gaps")
        if not any_demoted:
            emit(src, "note",
                 f"verdict: {verdict.get('verdict','').upper()} "
                 f"({verdict.get('confidence','?')})")

    status = "incomplete_budget" if over_budget else "completed"
    emit(src, "done",
         f"{status} (steps={state['steps']}/{state['max_steps']}, "
         f"calls={state['tool_calls_made']}/{state['max_tool_calls']})")
    return {
        "status": status,
        "final_answer": final_answer,
        "verdict": verdict,
    }
