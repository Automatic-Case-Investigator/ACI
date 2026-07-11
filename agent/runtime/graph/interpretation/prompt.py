"""Prompt rendering blocks for the interpret model call (SYSTEM/DEVELOPER + USER/CONTEXT)."""
from __future__ import annotations

from langchain_core.messages import AIMessage, ToolMessage
from .ledger import _coerce_confirmed_findings, _coerce_string_list, _render_query_trials
from .pivots import _coerce_pivot


def _compromise_block(compromise_facts: list[str]) -> str:
    """Confirmed compromise indicators the DECODE layer already extracted onto the board —
    proven, deterministic, and independent of raw position or the 24KB tool-result cap.
    Surfaced prominently so interpret dispositions them even when the raw event that carried
    them sat deep in a flooded result the model never saw (diagnosed: a decoded webshell
    cracking command boarded at offset 32KB was never addressed). Persist per-cycle: the set
    is narrow and high-signal (decoded shells/commands), so re-surfacing until it is folded
    into a finding is correct, not noise."""
    facts = [c for c in (compromise_facts or []) if c][:6]
    if not facts:
        return ""
    lines = "\n".join(f"- {c}" for c in facts)
    return (
        "CONFIRMED COMPROMISE INDICATORS already on your board (the decode layer extracted "
        "these from RAW evidence — they are proven facts, not hypotheses, and may come from a "
        "part of a flooded result you did not see). You MUST disposition EACH: state what it "
        "proves and fold it into a confirmed finding, or record a concrete reason it is out of "
        "scope. Do NOT ignore them, and NEVER conclude a negative that contradicts them:\n"
        f"{lines}\n\n"
    )
def _notable_events_block(observation: dict) -> str:
    """The retrieved events rendered as a readable list at the TOP of the prompt, so the
    interpreter reasons over WHAT came back (paths, commands, statuses, users, decoded
    payloads) instead of only the hit count buried in the observation JSON."""
    digest = observation.get("evidence_digest") or []
    if not digest:
        return (
            "Notable events retrieved this batch:\n"
            "(none — the batch returned aggregates/counts or nothing; reason about what that "
            "absence or distribution means for the objective.)\n\n"
        )
    lines = "\n".join(f"- {line}" for line in digest[:8])
    return (
        "Notable events retrieved this batch (READ THESE FIRST — reason over their content, "
        "not just how many hits came back):\n"
        f"{lines}\n\n"
    )
def _trials_block(ledger: dict) -> str:
    """The task's outcome-annotated query history, rendered for the interpreter to reason
    over its own failures — the surface the deterministic stagnation signals cannot carry."""
    rendered = _render_query_trials(ledger.get("query_trials") or [])
    if not rendered:
        return ""
    return (
        "Your query trials so far this task (discriminator @ window -> outcome; indented `·` "
        "lines are the actual events that trial retrieved). REASON ACROSS THEM — over what "
        "each query RETURNED, not just its hit count — before proposing the next query:\n"
        f"{rendered}\n"
        "- A discriminator that keeps returning `empty` is a MATCHING-LOGIC failure, not a "
        "real absence: that value is not present as you are spelling it. Stop re-issuing it; "
        "`profile_field` the field to see the values that DO exist, or `must_not` the alert's "
        "own value and read the residue.\n"
        "- A discriminator that keeps returning `flood`/`truncated` needs a narrower "
        "discriminator, not a repeat.\n"
        "- A window that keeps returning the same thing is exhausted: move it forward/backward "
        "along the burst map, do not re-query it.\n"
        "- Choose a (discriminator, window) pair your trials have NOT already refuted.\n\n"
    )
def _batch_tool_outputs(messages: list) -> str:
    """The FULL tool outputs of the current batch — the exact (already 24KB-capped) results
    the acting agent received, so the interpreter analyzes what was actually retrieved rather
    than a lossy digest. Gathers the trailing contiguous ToolMessages (the batch that just
    ran), newest last, and does NOT re-truncate them."""
    trailing: list = []
    for msg in reversed(messages or []):
        if isinstance(msg, ToolMessage):
            trailing.append(msg)
        elif isinstance(msg, AIMessage):
            # Stop at the AIMessage that issued this batch's tool calls.
            if trailing:
                break
    if not trailing:
        return ""
    blocks: list[str] = []
    for msg in reversed(trailing):
        name = getattr(msg, "name", "") or "tool"
        content = getattr(msg, "content", "") or ""
        blocks.append(f"### {name}\n{content}")
    return "\n\n".join(blocks)
def _render_task(task: dict | None) -> str:
    t = task or {}
    title = " ".join(str(t.get("title") or "").split()) or "(untitled)"
    desc = str(t.get("description") or "").strip()
    return f"{title}\n{desc}" if desc else title
def _render_confirmed_findings(findings) -> list[str]:
    out: list[str] = []
    for f in _coerce_confirmed_findings(findings, limit=8):
        summary = f.get("summary") or ""
        events = f.get("event_ids") or []
        out.append(f"{summary}{f' [{events[0]}]' if events else ''}")
    return out
def _where_you_are(task: dict | None, ledger: dict) -> str:
    """The durable per-task state rendered as readable prose (replaces the raw ledger JSON
    dump) — a weak model reasons over this far better than ~18 machine fields. Only the
    reasoning-relevant fields; control keys (next_action/evidence_state/stop_state/pivot
    bookkeeping) drive the graph, not the model's prose."""
    lines = ["Where you are on this task (your progress so far):"]
    lines.append(f"- Objective: {ledger.get('objective') or (task or {}).get('title') or '(unspecified)'}")
    if (ledger.get("stop_condition") or "").strip():
        lines.append(f"- Success criteria: {ledger['stop_condition']}")
    if (ledger.get("hypothesis") or "").strip():
        lines.append(f"- Working hypothesis: {ledger['hypothesis']}")
    confirmed = _render_confirmed_findings(ledger.get("confirmed_findings"))
    if confirmed:
        lines.append("- Confirmed so far:")
        lines += [f"    * {c}" for c in confirmed]
    gaps = _coerce_string_list(ledger.get("remaining_gaps"), limit=6)
    blocker = " ".join(str(ledger.get("blocker") or "").split())
    open_items = gaps + ([blocker] if blocker and blocker.lower() not in {g.lower() for g in gaps} else [])
    if open_items:
        lines.append("- Open / unproven: " + "; ".join(open_items))
    pivot = _coerce_pivot(ledger.get("primary_pivot"))
    if pivot:
        lines.append(
            f"- Primary pivot: {pivot.get('field')}={pivot.get('value')} "
            f"({pivot.get('source_level')}/{pivot.get('role')}, failures={pivot.get('failure_count')})"
        )
    if (ledger.get("next_step_instruction") or "").strip():
        lines.append(f"- Your last planned next step: {ledger['next_step_instruction']}")
    return "\n".join(lines) + "\n\n"
def _signals_this_batch(observation: dict) -> str:
    """The deterministic signals + recommended moves for this batch, as a compact line
    (replaces the raw observation JSON dump — the rest of the observation is already
    rendered by the notable-events / trials / full-tool-output blocks)."""
    signals = observation.get("signals") or []
    moves = observation.get("recommended_moves") or []
    if not (signals or moves):
        return ""
    lines = ["Signals this batch:"]
    if signals:
        lines.append("- " + ", ".join(str(s) for s in signals))
    lines += [f"- suggested: {m}" for m in moves[:4]]
    return "\n".join(lines) + "\n\n"
def _interpret_system_prompt() -> str:
    """The STABLE SystemMessage for the interpret model: `# SYSTEM` (identity + the no-tools
    constraint) and `# DEVELOPER` (the reasoning principles + the output contract). Constant
    across cycles → one cache-friendly prefix. Provider-agnostic — plain text + headers, no
    provider-specific role. The volatile task/state/evidence live in the USER message
    (`_interpret_context`)."""
    return (
        "# SYSTEM\n"
        "You are a metacognitive interpreter for a SOC investigation agent. You do NOT call "
        "tools. Read the agent's current state and the latest tool results (in the USER "
        "message), decide whether the task advanced, and write a short structured "
        "interpretation that steers the next action. Return ONLY the requested template.\n\n"
        "# DEVELOPER\n\n"
        "Principles:\n"
        "1. Separate facts from inference.\n"
        "2. Judge advancement against the task objective and stop condition, not against whether "
        "a tool merely returned data. Completion is a claim about the OBJECTIVE, not about "
        "retrieval: on your FIRST cycle for a task, decompose its objective into the concrete "
        "outcomes that must EACH be true for the task to be done, and write them under 'Success "
        "criteria'. On later cycles keep the criteria stable and mark each one met (naming the "
        "evidence that meets it) or unmet. A criterion is MET when it is ANSWERED — either a "
        "confirmed positive OR a CAPABLE confirmed negative (you searched where the evidence "
        "would appear, with the right discriminator and window, and it is not there). A capable "
        "negative is a finished answer; do NOT keep hunting for a positive it has already ruled "
        "out. Declare 'complete' when every criterion is answered this way (or explicitly "
        "surrendered under 'What remains unproven or blocked'); retrieving more events related to "
        "the objective does not by itself complete it, and neither does the existence of more you "
        "COULD look at.\n"
        "2b. STAY IN SCOPE. This task has ONE objective. Adjacent entities, hosts, or threads you "
        "notice are New Leads for OTHER tasks, not reasons to keep THIS task open — the "
        "investigation continues in other tasks. Conclude the moment THIS objective is answered, "
        "even if the broader case is not fully understood. The tool-call budget is a CEILING, not "
        "a quota: reaching evidence that answers the criteria means STOP, regardless of how many "
        "calls remain.\n"
        "3. READ THE ACTUAL EVENTS in the FULL tool outputs (in the CONTEXT section of the USER "
        "message) — do not rely on summaries or "
        "hit counts. Inspect every retrieved event's real fields (paths, commands, HTTP status, "
        "query parameters, decoded payloads, users, rule), decode any encoded parameter, and name "
        "the specific ones that matter, classifying each as expected/benign vs. suspicious and "
        "WHY. A concrete payload-bearing detail is strong evidence even from a low-severity or "
        "capped result.\n"
        "4. Preserve confirmed facts separately from unresolved objectives. If raw evidence "
        "confirms a meaningful fact, keep it as a finding even when another part of the task "
        "remains incomplete; move unresolved pieces to gaps or hypotheses instead of erasing "
        "the fact.\n"
        "5. Do not overfit to one exact artifact unless the latest evidence truly verifies it as the right discriminator.\n"
        "6. If the latest batch only re-confirms the same stage, say what adjacent stage or broader behavior should be examined next.\n"
        "7. Triage is BOUNDED but must be GROUNDED. Triage does not need exhaustive closure "
        "of the whole chain — but it may only conclude once it has actually grounded the "
        "alert in RETRIEVED evidence: it has loaded the alert record and read its raw fields, "
        "profiled the discriminating fields, read the specific raw events that confirm or "
        "refute the alert's claim, and correlated the key entities (host, user, source IP, "
        "rule family) the case warrants — OR it has capably established a confirmed negative "
        "(searched where the evidence would appear, with the right discriminator and window, "
        "and it is not there). Consulting memory/context (patterns, feedback, baselines) or "
        "running a single empty or over-broad query is NOT grounding and does NOT justify "
        "completion — it is orientation, and orientation is where triage starts, not where it "
        "stops. Once the alert IS grounded, do not keep drilling: a noisy, capped, or "
        "contradictory result at that point is itself a 'needs investigation' cue — record the "
        "residual uncertainty as an investigation-plan item and hand off. Do NOT vote to "
        "complete until this grounding standard is met.\n"
        "8. Investigation has the higher bar: each task should converge on direct evidence, "
        "a capable confirmed negative, or a concrete follow-up lead. Recover from failures "
        "by changing representation, entity, or window; do not repeat the same failed query "
        "shape.\n"
        "9. Reason over your query trials as a SET (in the CONTEXT section). What have "
        "they collectively ruled out? A value that keeps returning empty means your matching "
        "logic is wrong (profile the real values / subtract the alert's own value); a window "
        "that keeps returning the same means move it. Never propose a (discriminator, window) "
        "your trials already refuted.\n\n"
        "Output — write your interpretation in plain text using EXACTLY this structure:\n"
        "What the last batch showed:\n"
        "<name the specific notable events in the CONTEXT and what each one means; separate what "
        "they prove (fact) from what they suggest (inference); flag anything potentially important>\n\n"
        "Did it advance the task:\n"
        "<yes or no, then one short reason>\n\n"
        "Success criteria:\n"
        "<the task objective decomposed into the outcomes that must each be TRUE for the task "
        "to be done — one per line, each marked met (with the evidence that meets it) or unmet. "
        "Derive them on the first cycle; keep them stable afterwards>\n\n"
        "Working hypothesis:\n"
        "<one short paragraph>\n\n"
        "What remains unproven or blocked:\n"
        "<one short paragraph>\n\n"
        "Suggested next direction:\n"
        "<one concrete next evidence target that FOLLOWS the most interesting event you just "
        "saw — reference the specific value/event (e.g. retrieve and decode the full_log of the "
        "200-status hit on that path), not a generic move>\n\n"
        "Stop state:\n"
        "<continue | complete | negative. Choose 'complete' as soon as every success criterion "
        "is answered (positive OR capable confirmed negative) or surrendered as a gap — do NOT "
        "continue merely because budget or adjacent threads remain. Choose 'negative' when the "
        "objective is a capable confirmed negative. Choose 'continue' ONLY when a specific "
        "criterion is still unanswered AND you named a concrete query that would answer it>\n"
    )
def _interpret_context(
    task: dict | None, ledger: dict, observation: dict, extra_context: str,
    tool_outputs: str = "", compromise_facts: list[str] | None = None,
) -> str:
    """The VOLATILE HumanMessage for the interpret model: `# USER` (the current task) and
    `# CONTEXT` (durable state as prose, then evidence most-durable-first, then this batch's
    raw ground truth). Rebuilt every cycle."""
    return (
        "# USER\n"
        f"Current task:\n{_render_task(task)}\n\n"
        "# CONTEXT\n\n"
        f"{_where_you_are(task, ledger)}"
        f"{_compromise_block(compromise_facts)}"
        f"{_notable_events_block(observation)}"
        f"{_trials_block(ledger)}"
        f"{_prompt_steering(ledger, observation)}"
        f"{_signals_this_batch(observation)}"
        "Full tool outputs this batch (the complete results the agent received — analyze "
        "these directly, this is the ground truth of what was retrieved):\n"
        f"{tool_outputs or '(no tool output this batch)'}\n\n"
        f"Additional context:\n{extra_context or '(none)'}\n"
    )
def _prompt(
    task: dict | None, ledger: dict, observation: dict, extra_context: str,
    tool_outputs: str = "", compromise_facts: list[str] | None = None,
) -> str:
    """The interpret prompt as a single combined string (SYSTEM+DEVELOPER then USER+CONTEXT).
    `interpret()` sends these as two separate messages; this combined form is kept for
    tests/debug and any caller that wants the whole prompt as one string."""
    return (
        _interpret_system_prompt()
        + "\n\n"
        + _interpret_context(task, ledger, observation, extra_context, tool_outputs, compromise_facts)
    )
def _prompt_steering(ledger: dict, observation: dict) -> str:
    """Adaptive steering injected above the ledger dump: on a stuck direction, mark the
    prior suggestion FAILED so the model stops echoing it; on a flooded result with an
    isolated discriminator, point it at the returned sample and candidate deviations."""
    blocks: list[str] = []
    if "NO_PROGRESS" in (observation.get("signals") or []):
        blocks.append(
            "CONVERGENCE WARNING: this task has run many cycles without producing a new "
            "confirmed finding — it is WANDERING (varying the query without closing in). More "
            "queries are not the fix; a decision is. In 'Stop state', either declare 'complete' "
            "(or 'negative' — a well-scoped confirmed negative is a finished answer) if the "
            "success criteria are already answered by what you hold, or, if exactly one "
            "concrete evidence-backed thread is genuinely unexplored, name that single query as "
            "your suggested next direction. Do not keep hopping across entities and windows."
        )
    if "STUCK" in (observation.get("signals") or []):
        prior = ledger.get("next_step_instruction") or ""
        blocks.append(
            "!! THIS DIRECTION HAS FAILED. The previous suggested direction"
            + (f" ({prior[:160]})" if prior else "")
            + " has returned nothing for several cycles in a row — it is EXHAUSTED. Do NOT "
            "restate it or reword it. Your 'Suggested next direction' MUST change the approach: "
            "a different field (src↔dst user/IP), profiling `rule.groups`/`rule.id` to find the "
            "REAL rule that fired (never re-guess a rule.id number that already returned zero), a "
            "wider window, or a questioned premise (did this event occur on THIS host at all?)."
        )
    disc = observation.get("discriminator")
    if isinstance(disc, dict) and disc.get("field") and disc.get("minority") is not None:
        values = ", ".join(str(v) for v in (disc.get("minority_values") or [])[:8])
        sample_ids = ", ".join(str(v) for v in (disc.get("sample_event_ids") or [])[:6])
        sample_part = f" Returned sample events: {sample_ids}." if sample_ids else ""
        blocks.append(
            f"FLOOD DEVIATION SAMPLE: the last flooded result varies along `{disc['field']}` — "
            f"dominant `{disc.get('dominant')}` is the flood value; minority candidates are "
            f"{values or disc['minority']}.{sample_part} Inspect and decode the returned sample, "
            "rank candidates by semantic fit to the objective, and only then choose a follow-up "
            f"query such as `{disc['field']}=<chosen candidate>` or `must_not` the dominant. Do "
            "not default back to the alert's own rule.id."
        )
    return ("\n".join(blocks) + "\n\n") if blocks else ""
