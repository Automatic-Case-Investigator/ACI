from __future__ import annotations

"""Flat, orchestrator-style evidence loop for the triage agent.

Replaces the `think → use_tools → interpret → assess` cycle for triage with a
single node that keeps ONE growing message history, the way `orchestrator/driver.py`
does. The graph path stays `seed → triage_think ⇄ use_tools → finish`, so
`use_tools` (tool dispatch, caching, time-window guard, artifact/TI pipeline) and
the whole `finish → verdict_contract → reassess_verdict → publish_finish` tail are
reused unchanged. The investigation agent's path is untouched.

Why flat: the graph loop wiped `messages` to `[]` on every continuation cycle and
rebuilt the prompt from ≤8 ledger bullets, so the model choosing the next tool call
had never seen a raw event. Cross-cycle synthesis — linking a `uid=33` su origin
from one query to a decoded command in another — was structurally impossible.
The orchestrator, which keeps every raw tool result in context until compaction,
consistently out-triaged the triage agent for exactly that reason.

What the ledger machinery bought (and what is rebuilt here deterministically,
because a flat loop no longer has an interpret node to enforce it):
  - an evidence floor, so the model cannot conclude without reading raw events
  - a report-shape contract, so the handoff is a durable three-section report
  - a budget ceiling, enforced by the caller via `max_steps` / `max_tool_calls`
"""

import json

from langchain_core.messages import HumanMessage, SystemMessage

from ..analysis.intent import generate_public_intent
from ..infra.logbus import emit, src_label, summarize_think
from .nodes_flow._const import _EVIDENCE_TOOLS
from .parsing import _missing_triage_sections
from .sanitize import _sanitize_history, _sanitize_message
from .state import AgentState
from .toolio import (
    _compact_history,
    _emit_node_entry,
    _invoke_bound_model,
    _model_tools_for_agent,
    _should_compact,
    _track_input_tokens,
)

# Minimum distinct evidence-tool calls before a final answer is accepted. The
# interpret node used to enforce depth by judgement; with it gone this is the
# deterministic backstop against a report written from the alert record alone.
_MIN_EVIDENCE_CALLS = 3

# Bounded in-node corrections. A deficient final answer (too little evidence, or
# a malformed report) is nudged rather than routed, so the graph stays a simple
# two-state loop: this node either emits tool calls or a finished report.
_MAX_CORRECTIONS = 2


def build_triage_objective(state: AgentState) -> str:
    """The anchor message: the analyst's literal question plus how to answer it.

    Sent ONCE, as message[1], and never replayed — mirroring the orchestrator,
    whose message[1] is the analyst's question. The methodology lives here rather
    than in a per-cycle nudge so it cannot be re-read as a checklist to restart.
    """
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
    question = (state.get("question") or "").strip()
    entity = (state.get("source_entity_id") or state.get("case_id") or "").strip()

    return (
        "# USER\n"
        f"The analyst asked: {question}\n\n"
        f"Entity under triage: {entity or '(resolve it from the question)'}\n\n"
        "Answer THAT question, grounded in raw evidence you retrieved. Everything "
        "below is how to get there — it is not a checklist to tick off.\n\n"
        "Ground the entity first. Let the analyst's own wording (case / alert / "
        "event) choose the first lookup — do not guess from the id's shape. If they "
        "called it an alert, load the actual ALERT record and read its raw fields; "
        "if that lookup fails, try the case lookup, then a SIEM search on the "
        "identifier itself.\n\n"
        "Then run the analyst loop on the concrete pivots (host, user, source IP, "
        "rule family):\n"
        "- PROFILE the discriminating fields (`profile_field`) to see what values "
        "actually exist and what deviates from the baseline, before you filter on them.\n"
        "- RETRIEVE AND READ the specific raw events behind the hits (`get_event` on "
        "the ids a `search`/`search_keyword` returns) — open the actual event and "
        "read its fields (command, path, status, user, decoded payload). A hit count "
        "is not evidence, and neither is an aggregate: `correlate_entity` tells you "
        "WHICH events matter, then you must go read them.\n"
        "- CORRELATE the key entities (`correlate_entity`) to follow the chain the "
        "alert sits in — the same user/host/IP across roles and adjacent time.\n\n"
        "When a query names an artifact you have not read — an event id, a command, "
        "a path, an encoded payload — reading it is the next step, not a follow-up "
        "for someone else. The decisive evidence is usually DOWNSTREAM of the alert "
        "that fired, not inside it.\n\n"
        "Let historical context INFORM this loop, not replace it: known FP/TP "
        "patterns, prior analyst feedback, and entity baselines shape your "
        "disposition, but they are context, not evidence — never conclude from them "
        "without reading the raw events.\n\n"
        "Derive an absolute time window around the case `date` field or alert "
        f"timestamp using the configured default vicinity window of ±{vicinity_hours} "
        "hours unless the evidence already gives an explicit absolute range; start "
        "tighter and widen toward that bound only if empty.\n\n"
        "You are done when the analyst's question is ANSWERED from raw evidence — "
        "not when a fixed number of steps has run, and not when you have merely "
        "gathered context around the alert. Triage is bounded: once the question is "
        "answered, or you have capably established the evidence is not there, stop "
        "and write the report. Carry genuinely unresolved adjacent threads into the "
        "investigation plan rather than chasing them here.\n\n"
        + _report_format_instruction(vicinity_hours)
    )


def _report_format_instruction(vicinity_hours: int) -> str:
    """The three-section handoff contract. Also reused as the correction nudge."""
    return (
        "When you are ready, write the full triage report as the TEXT of your reply, "
        "using the mandatory structured format:\n\n"
        "## Triage Summary\n"
        "## Key Evidence\n"
        "## Investigation Plan\n\n"
        "All three sections are required. In ## Investigation Plan, every item must "
        "include an explicit absolute time window. If an item does not have a "
        "narrower evidence-derived range, derive it from the configured default "
        f"vicinity window of ±{vicinity_hours} hours around the anchor timestamp. Do "
        f"not use ±24 hours unless this run's configured value is {vicinity_hours}. "
        "If an item intentionally uses a narrower range, state why. Do not paste raw "
        "JSON objects, entity dumps, or tool payloads as the report — explain what "
        "the evidence means in prose, then list concrete evidence as bullets. The "
        "platform generates the structured verdict JSON after your report; do not "
        "end your turn with tool calls only."
    )


def _evidence_call_count(messages: list) -> int:
    """Evidence-tool calls made so far, counted from the flat history.

    Deterministic and history-derived rather than a state counter, because the
    history IS the durable record in a flat loop.
    """
    seen = 0
    for msg in messages:
        for call in (getattr(msg, "tool_calls", None) or []):
            if call.get("name") in _EVIDENCE_TOOLS:
                seen += 1
    return seen


def _deficiency(text: str, messages: list) -> str:
    """Why this final answer is not acceptable yet, or '' if it is.

    Evidence depth is checked BEFORE report shape: a well-formatted report written
    from no evidence is the failure that matters, and telling the model to fix its
    headings first would let it re-submit the same ungrounded content.
    """
    evidence_calls = _evidence_call_count(messages)
    if evidence_calls < _MIN_EVIDENCE_CALLS:
        return (
            f"You have made only {evidence_calls} evidence "
            f"{'query' if evidence_calls == 1 else 'queries'} so far, which is not "
            "enough to ground a triage disposition. Do not write the report yet. Go read the "
            "raw events behind this alert — use `search`/`search_keyword` to locate "
            "them and `get_event` to open the specific ids, and follow the chain "
            "downstream of the alert. Make the tool calls now."
        )
    missing = _missing_triage_sections(text)
    if missing:
        return (
            "Your report is missing or has an empty "
            f"{', '.join(missing)} section. Rewrite the COMPLETE report from the "
            "evidence already in this conversation, keeping every section non-empty."
        )
    return ""


async def triage_think(state: AgentState, config) -> dict:
    """One cycle of the flat triage loop: narrate intent, then act or conclude."""
    tools = config["configurable"]["tools"]
    model = config["configurable"]["model"]
    system_prompt = config["configurable"].get("system_prompt", "")
    src = src_label(state["agent_name"])
    _emit_node_entry(src, "think", state)

    messages = _sanitize_history(list(state.get("messages") or []))
    if not messages:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=build_triage_objective(state)),
        ]

    model_tools = _model_tools_for_agent(state["agent_name"], tools, None)
    bound = model.bind_tools(model_tools)
    ctx_tokens = state.get("ctx_tokens", 0)

    if _should_compact(ctx_tokens):
        emit(src, "note", f"context compaction triggered ({ctx_tokens:,} tokens)")
        messages = await _compact_history(messages, bound, state["agent_name"])
        ctx_tokens = 0

    # Per-cycle public intent, generated from the FULL history — the orchestrator's
    # planning step. Re-reading everything retrieved so far is what lets the model
    # connect evidence across cycles instead of reacting to the latest batch.
    intent = await generate_public_intent(
        model,
        messages,
        source=src,
        sequence=state["steps"] + 1,
        task_title=(state.get("question") or "").strip(),
        available_tools=[getattr(t, "name", "") for t in model_tools],
    )
    if intent.text:
        messages = messages + [HumanMessage(content=(
            "[Public intent already shown to the analyst]\n"
            f"{intent.text}\n\n"
            "Perform that action now. Make the tool calls needed to answer the "
            "analyst's question, or write your triage report as text if the "
            "evidence you hold already answers it."
        ))]

    response = await _invoke_bound_model(bound, messages, state["agent_name"])
    _sanitize_message(response)
    ctx_tokens = _track_input_tokens(response, src, ctx_tokens)
    messages = messages + [response]

    # Tool calls: hand off to `use_tools`, which appends results to this same history.
    if getattr(response, "tool_calls", None):
        text = (response.content or "").strip()
        if text:
            emit(src, "think", summarize_think(text), detail=text)
        return {
            "messages": messages,
            "steps": state["steps"] + 1,
            "ctx_tokens": ctx_tokens,
        }

    # No tool calls: the model is concluding. Accept only a grounded, well-formed
    # report; otherwise correct it in-node so routing stays a simple two-state loop.
    text = (response.content or "").strip()
    for _ in range(_MAX_CORRECTIONS):
        budget_left = (
            state["steps"] + 1 < state["max_steps"]
            and state["tool_calls_made"] < state["max_tool_calls"]
        )
        problem = _deficiency(text, messages) if budget_left else ""
        if not problem:
            break
        emit(src, "note", f"triage self-correction: {problem.split('.')[0][:110]}")
        messages = messages + [HumanMessage(content=problem)]
        response = await _invoke_bound_model(bound, messages, state["agent_name"])
        _sanitize_message(response)
        ctx_tokens = _track_input_tokens(response, src, ctx_tokens)
        messages = messages + [response]
        if getattr(response, "tool_calls", None):
            # The correction sent it back for evidence — resume the normal loop.
            return {
                "messages": messages,
                "steps": state["steps"] + 1,
                "ctx_tokens": ctx_tokens,
            }
        text = (response.content or "").strip()

    # Last resort — the shape guard `assess` used to own. Corrections are advisory
    # (the model may ignore them); this is not. Without it a raw blob reaches the
    # verdict contract as the handoff, which is what the ledger loop protected against.
    missing = _missing_triage_sections(text)
    if missing:
        forced = await _force_report_shape(model, messages, state, src, missing)
        # Only take the rewrite if it is actually better shaped — a still-broken
        # model must not be allowed to replace one malformed answer with another.
        if forced and len(_missing_triage_sections(forced)) < len(missing):
            text = forced

    if text:
        emit(src, "think", summarize_think(text), detail=text)
    return {
        "messages": messages,
        "steps": state["steps"] + 1,
        "ctx_tokens": ctx_tokens,
        "final_answer": text,
    }


async def _force_report_shape(
    model, messages: list, state: AgentState, src: str, missing: list[str],
) -> str:
    """Tool-free synthesis of a durable three-section report from the conversation.

    Keeps the wording the `assess` shape guard used, so the repair instruction the
    model sees for a malformed triage handoff is unchanged by the move to the flat loop.
    """
    vicinity_hours = int(state.get("default_vicinity_window_hours") or 24)
    emit(src, "note",
         f"triage report malformed, missing {', '.join(missing)} — requesting text synthesis")
    try:
        text_only = model.bind_tools([])
        prompt = HumanMessage(content=(
            "Your previous reply was not a valid triage handoff report. "
            "Rewrite the triage handoff as a complete text report now. Do not make "
            "any further tool calls, and do not paste raw JSON or entity dumps as the "
            "report body — ground it only in the tool results already in this "
            "conversation.\n\n"
            + _report_format_instruction(vicinity_hours)
        ))
        resp = await _invoke_bound_model(
            text_only, _sanitize_history(messages + [prompt]), state["agent_name"],
        )
        _sanitize_message(resp)
        return (resp.content or "").strip()
    except Exception as exc:  # noqa: BLE001 - never fail the run on the safety net
        emit(src, "error", f"triage report synthesis failed: {exc}")
        return ""
