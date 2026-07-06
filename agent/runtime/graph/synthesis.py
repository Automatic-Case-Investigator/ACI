from __future__ import annotations

import asyncio
import json
import re

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ..infra.logbus import emit, src_label, summarize_result

from .board import _entry_line
from .parsing import _FINDINGS_RE, _HYPOTHESES_RE, _fact_dedup_key, _is_none_bullet, _is_provenance_only, _looks_like_lead, _normalize_fact_key, _section_body, _strip_markers
from .sanitize import _normalize, _sanitize_message
from .state import AgentState
from .toolio import _MAX_SYNTHESIS_FINDINGS_CHARS, _SEED_TASK_TITLE, _call, _is_error_tool_result
from .validation import _derive_report_guardrails
from ..analysis.kill_chain import KILL_CHAIN_ORDER, _CORE_PHASES



def _execution_record(messages: list) -> str:
    """Build a factual completion record from tool messages already in history."""
    entries: list[str] = []
    for message in messages:
        if not isinstance(message, ToolMessage):
            continue
        name = getattr(message, "name", "") or "tool"
        content = _normalize(getattr(message, "content", "") or "")
        entries.append(f"- `{name}`: {summarize_result(name, content)}")

    if entries:
        return (
            "The task reached completion without a final narrative from the agent.\n\n"
            "**Recorded tool activity:**\n" + "\n".join(entries) +
            "\n\nNo additional conclusion was supplied. Review the recorded tool "
            "results and linked artifacts before treating the task as a substantive finding."
        )
    return (
        "The task reached completion without a final narrative and without recorded "
        "tool activity. No findings or conclusion were supplied."
    )


async def _build_investigation_summary(state: AgentState, tmap: dict, model=None) -> str:
    """Read the task queue and board, then compile the final investigation report.

    Produces a synthesized SOC analyst report (verdict, executive summary, timeline,
    scope/impact, recommendations, open gaps) via one model call over the COMPLETE
    board, followed by the deterministic structured findings as an appendix so the
    full grounded detail is always preserved. Runs at the end of every investigation
    so the orchestrator and analyst receive a complete, decision-useful picture.
    """
    # --- task queue ---
    list_fn = tmap.get("list_tasks")
    tasks: list[dict] = []
    if list_fn:
        raw = await _call(list_fn, {
            "case_id": state["case_id"],
            "run_id": state["run_id"],
            "agent_name": state["agent_name"],
        })
        if not _is_error_tool_result(raw):
            try:
                data = json.loads(raw)
                tasks = data if isinstance(data, list) else data.get("tasks", [])
            except Exception:
                pass

    completed = [t for t in tasks if t.get("status") == "completed"
                 and _SEED_TASK_TITLE not in (t.get("title") or "").lower()]
    incomplete = [t for t in tasks if t.get("status") not in ("completed", "dismissed")
                  and _SEED_TASK_TITLE not in (t.get("title") or "").lower()]

    # --- board ---
    get_board_fn = tmap.get("get_board")
    artifacts: list[dict] = []
    facts: list[dict] = []
    hypotheses: list[dict] = []
    ti_enrichments: list[dict] = []
    kill_chain_entries: list[dict] = []
    if get_board_fn:
        raw = await _call(get_board_fn, {})
        if not _is_error_tool_result(raw):
            try:
                data = json.loads(raw)
                entries = data.get("entries", []) if isinstance(data, dict) else []
                artifacts = [e for e in entries if e.get("kind") == "artifact"]
                facts = [e for e in entries if e.get("kind") == "fact"]
                hypotheses = [e for e in entries if e.get("kind") == "hypothesis"]
                ti_enrichments = [e for e in entries if e.get("kind") == "ti_result"]
                kill_chain_entries = [e for e in entries if e.get("kind") == "kill_chain"]
            except Exception:
                pass

    # --- compose deterministic structured findings (the grounded appendix) ---
    lines: list[str] = [
        f"# Structured Findings — Case {state['case_id']}",
        f"**Run:** {state['run_id']}  \n**Question:** {state['question']}",
        "",
    ]

    # Lead with the confirmed findings so the most important results (e.g. a
    # confirmed reverse shell) are at the top, not buried in a per-task appendix.
    # Built deterministically from the board: all facts + confirmed hypotheses.
    # Collapse near-duplicate facts: the model restates the same fact across
    # tasks with only the event-id / timestamp differing, so dedup on a
    # volatility-stripped key (not exact text) and drop placeholder negatives.
    key_findings: list[str] = []
    seen_findings: set[str] = set()
    for fact in facts:
        content = (fact.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _is_provenance_only(content):
            continue
        key = _fact_dedup_key(content) or content.lower()
        if key in seen_findings:
            continue
        seen_findings.add(key)
        src = f" [{fact['source']}]" if fact.get("source") else ""
        key_findings.append(f"- {content}{src}")
    for hyp in hypotheses:
        if hyp.get("status") != "confirmed":
            continue
        content = (hyp.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _looks_like_lead(content):
            continue
        key = _normalize_fact_key(content) or content.lower()
        if key in seen_findings:
            continue
        seen_findings.add(key)
        key_findings.append(f"- {content} (confirmed)")
    derived_findings, report_guardrails = _derive_report_guardrails(
        artifacts, facts, hypotheses, completed
    )
    for finding in derived_findings:
        key = finding.lower()
        if key not in seen_findings:
            seen_findings.add(key)
            key_findings.append(finding)

    lines.append("## Key Findings")
    if key_findings:
        lines.extend(key_findings)
    else:
        lines.append("- No confirmed findings; see Hypotheses and Completed Tasks below.")
    lines.append("")

    if artifacts:
        lines.append("## Found Artifacts")
        for artifact in artifacts:
            src = f" [{artifact['source']}]" if artifact.get("source") else ""
            lines.append(f"- {artifact['content']}{src}")
        lines.append("")

    # Dedup + drop placeholder negatives so the appendix mirrors Key Findings.
    fact_lines: list[str] = []
    seen_facts: set[str] = set()
    for fact in facts:
        content = (fact.get("content") or "").strip()
        if not content or _is_none_bullet(content) or _is_provenance_only(content):
            continue
        key = _fact_dedup_key(content) or content.lower()
        if key in seen_facts:
            continue
        seen_facts.add(key)
        src = f" [{fact['source']}]" if fact.get("source") else ""
        fact_lines.append(f"- {content}{src}")
    if fact_lines:
        lines.append("## Confirmed Facts")
        lines.extend(fact_lines)
        lines.append("")

    # Collapse duplicate hypotheses onto one entry, preferring a resolved
    # status (confirmed/refuted) over open so the same claim never appears as
    # both [open] and [refuted]. Drop placeholder negatives and stray leads.
    _STATUS_RANK = {"confirmed": 3, "refuted": 2, "open": 1}
    hyp_by_key: dict[str, dict] = {}
    for hyp in hypotheses:
        raw = (hyp.get("content") or "").strip()
        # The model often embeds the status (and confidence) as a literal prefix
        # inside the content (`[confirmed/medium] ...`). Peel it for clean display
        # and trust it over a stale DB status when present.
        content, embedded_status = _strip_markers(raw)
        if not content or _is_none_bullet(content) or _looks_like_lead(content):
            continue
        status = embedded_status or hyp.get("status", "open")
        key = _normalize_fact_key(content) or content.lower()
        prev = hyp_by_key.get(key)
        if prev is None or _STATUS_RANK.get(status, 0) > _STATUS_RANK.get(prev["status"], 0):
            hyp_by_key[key] = {
                "content": content,
                "status": status,
                "confidence": hyp.get("confidence", "medium"),
            }
    if hyp_by_key:
        lines.append("## Hypotheses")
        for h in hyp_by_key.values():
            lines.append(f"- [{h['status']}/{h['confidence']}] {h['content']}")
        lines.append("")

    if ti_enrichments:
        lines.append("## TI Enrichment (advisory)")
        for e in ti_enrichments:
            ref = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- {e['content']}{ref}")
        lines.append("")

    if completed:
        lines.append("## Completed Tasks")
        for t in completed:
            lines.append(f"### {t.get('title', '(untitled)')}")
            summary = (t.get("summary") or "").strip()
            if summary:
                lines.append(summary)
            lines.append("")

    if incomplete:
        lines.append("## Incomplete / Pending Tasks")
        for t in incomplete:
            status = t.get("status", "unknown")
            lines.append(f"- [{status}] {t.get('title', '(untitled)')}")
        lines.append("")

    if not completed and not artifacts and not facts and not hypotheses and not ti_enrichments:
        lines.append("No tasks completed and no Findings Board entries were recorded.")

    structured = "\n".join(lines)

    # Synthesize a SOC analyst report on top of the grounded data. The model sees
    # the COMPLETE board + task summaries (never truncated); the structured findings
    # are kept as an appendix so nothing is lost if the synthesis is terse.
    kill_chain_content = kill_chain_entries[-1].get("content") if kill_chain_entries else ""
    narrative = await _synthesize_analyst_report(
        model, state, key_findings, facts, hypotheses, completed, report_guardrails,
        phase_scaffold=_phase_scaffold(kill_chain_content),
    )
    if narrative:
        return f"{narrative}\n\n---\n\n# Appendix — Structured Findings\n\n{structured}"
    return structured


_ANALYST_REPORT_SYSTEM = (
    "You are a senior SOC analyst writing the final incident report from an "
    "investigation's confirmed findings. Use ONLY the evidence provided — never "
    "invent event IDs, IPs, hosts, users, timestamps, or facts. Correlate "
    "indicators: if a discovered destination/C2 address matches the original "
    "attacker source, or local privileged activity aligns in time with the alert, "
    "state the linkage explicitly. Be decisive and calibrated."
)


def _clip_findings_for_synthesis(findings: str) -> str:
    text = (findings or "").strip()
    if len(text) <= _MAX_SYNTHESIS_FINDINGS_CHARS:
        return text
    clipped = len(text) - _MAX_SYNTHESIS_FINDINGS_CHARS
    return (
        text[:_MAX_SYNTHESIS_FINDINGS_CHARS].rstrip()
        + f"\n\n[clipped {clipped} chars from Findings for synthesis prompt size]"
    )


def _task_summary_for_synthesis(summary: str) -> str:
    text = (summary or "").strip()
    findings_match = _FINDINGS_RE.search(text)
    hyp_match = _HYPOTHESES_RE.search(text)
    if findings_match and hyp_match:
        return (
            "## Findings\n"
            f"{_clip_findings_for_synthesis(_section_body(text, findings_match)) or '- None confirmed.'}\n\n"
            "## Hypotheses\n"
            f"{_section_body(text, hyp_match).strip() or '- No open hypotheses.'}"
        )
    if len(text) <= _MAX_SYNTHESIS_FINDINGS_CHARS:
        return text or "(no summary)"
    clipped = len(text) - _MAX_SYNTHESIS_FINDINGS_CHARS
    return (
        text[:_MAX_SYNTHESIS_FINDINGS_CHARS].rstrip()
        + f"\n\n[clipped {clipped} chars from unstructured task summary for synthesis prompt size]"
    )


def _phase_scaffold(kill_chain_content: str) -> str:
    """A kill-chain-ordered phase skeleton for the Phase-by-Phase section, derived
    deterministically from the kill-chain board line. Each ATT&CK phase the correlation
    tagged is marked EVIDENCE PRESENT; each core phase it did not is marked a gap. The
    model writes the prose under each and may confirm a phase from the facts even when
    MITRE tagging missed it (e.g. a `su` privilege escalation with no technique tag)."""
    content = (kill_chain_content or "").strip()
    if not content:
        return "(kill-chain not computed — derive the phase coverage from the confirmed facts below)"
    lines: list[str] = []
    for phase in KILL_CHAIN_ORDER:
        if phase in content:
            lines.append(f"- {phase}: EVIDENCE PRESENT (kill-chain correlation tagged this tactic)")
        elif phase in _CORE_PHASES:
            lines.append(f"- {phase}: no MITRE-tagged evidence (core phase — confirm from the facts or mark a gap)")
    return "\n".join(lines)


async def _synthesize_analyst_report(
    model, state: AgentState, key_findings: list[str],
    facts: list[dict], hypotheses: list[dict], completed: list[dict],
    report_guardrails: str = "",
    phase_scaffold: str = "",
) -> str:
    """One grounded model call → an analyst-grade narrative. '' on any failure."""
    if model is None:
        return ""
    # Cap lists so the synthesis prompt stays within small-model context limits.
    facts_txt = "\n".join(_entry_line(f) for f in facts[:60]) or "- (none)"
    hyps_txt = "\n".join(_entry_line(h) for h in hypotheses[:30]) or "- (none)"
    tasks_txt = "\n\n".join(
        f"### {t.get('title', '(untitled)')}\n{_task_summary_for_synthesis(t.get('summary') or '')}"
        for t in completed
    ) or "- (none)"
    findings_txt = "\n".join(key_findings) or "- (none)"
    guardrails_txt = report_guardrails or "- No deterministic severity/correlation guardrails derived."
    scaffold_txt = phase_scaffold or "(derive the phase coverage from the confirmed facts below)"
    prompt = (
        f"Case: {state['case_id']}\nAnalyst question: {state['question']}\n\n"
        f"## Key findings already derived\n{findings_txt}\n\n"
        f"## Deterministic analysis guardrails\n{guardrails_txt}\n\n"
        f"## Kill-chain phase coverage (scaffold for Phase-by-Phase Findings)\n{scaffold_txt}\n\n"
        f"## Confirmed facts (raw-evidence backed)\n{facts_txt}\n\n"
        f"## Hypotheses (with status)\n{hyps_txt}\n\n"
        f"## Completed investigation tasks\n{tasks_txt}\n\n"
        "Write the final report in markdown. Follow these authoring rules — they matter "
        "as much as the content:\n"
        "1. SEPARATE ALTITUDES. A fact (what the raw evidence proves), an inference (what it "
        "suggests), and an open question (what is unconfirmed) each have ONE home below. "
        "Never mix them in the same section.\n"
        "2. LINK EVIDENCE TO CONCLUSION. Every conclusion names the evidence that supports it "
        "and states a confidence.\n"
        "3. ONE REPRESENTATIVE EVENT ID PER CLAIM — not a dump of every ID; the appendix and "
        "evidence files hold the rest.\n"
        "4. STATE EACH FACT ONCE, at its home altitude; higher sections reference it, they do "
        "not restate it.\n\n"
        "Use EXACTLY these section headers, verbatim, with nothing appended to the header line:\n"
        "## Verdict\n"
        "## Executive Summary\n"
        "## Confirmed Timeline\n"
        "## Phase-by-Phase Findings\n"
        "## Open Gaps\n"
        "## Recommended Actions\n\n"
        "How to write each section:\n"
        "- Verdict: one line — compromise confirmed / suspected / false positive; severity "
        "(low/medium/high/critical); active or contained.\n"
        "- Executive Summary: 2-4 sentences a manager can act on, PROSE ONLY (no event IDs, no "
        "raw evidence). End with one line: 'Scope & impact: impact=<active/contained/unknown>, "
        "scope=<isolated/lateral_spread/unknown>' with a half-sentence justification. Every "
        "causal claim here must be consistent with Open Gaps.\n"
        "- Confirmed Timeline: chronological bullets of PROVEN events only, each with a timestamp "
        "and ONE representative event ID. If confirmed activity spans two or more clusters "
        "separated by more than 4 hours with no connecting artifact or session, flag it with a "
        "'⚠ Temporal gap: X hours — causal link unconfirmed' bullet. No interpretation here — "
        "that goes in Phase-by-Phase.\n"
        "- Phase-by-Phase Findings: walk the kill-chain phases from the scaffold above, in order. "
        "Use each phase as a '### <Phase>' sub-header and, for the phases that have evidence or "
        "are otherwise in scope, write: what the evidence shows, the evidence→conclusion link, and "
        "a confidence. A phase may be confirmed from the facts even if the scaffold shows no MITRE "
        "tag. This section is where interpretation and scope live — including Initial Access: state "
        "the confirmed source IP of the first suspicious login/session, whether it matches a later "
        "C2/callback address, and whether attribution holds; if the source IP was NOT retrieved, "
        "write '⚠ Initial access vector not established — source IP missing from telemetry.' and "
        "list it under Open Gaps.\n"
        "- Open Gaps: the single home for everything unconfirmed — unproven phases, open "
        "hypotheses, and missing/unavailable evidence, each with why. Must not contradict the "
        "Executive Summary or Phase-by-Phase confidences.\n"
        "- Recommended Actions: prioritized, concrete containment/remediation steps (numbered, "
        "highest urgency first).\n\n"
        "Do not append the structured JSON diagnosis verdict block; a separate "
        "verdict-contract step will generate the machine-readable verdict. Ground "
        "every narrative claim in the facts above. Follow the deterministic "
        "guardrails unless the facts explicitly contradict them."
    )
    _SYNTHESIS_TIMEOUT_SECS = 180
    try:
        resp = await asyncio.wait_for(
            model.ainvoke([
                SystemMessage(content=_ANALYST_REPORT_SYSTEM),
                HumanMessage(content=prompt),
            ]),
            timeout=_SYNTHESIS_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        return (getattr(resp, "content", "") or "").strip()
    except asyncio.TimeoutError:
        emit(src_label(state["agent_name"]), "warning",
             f"final report synthesis timed out ({_SYNTHESIS_TIMEOUT_SECS}s); using structured findings only")
        return ""
    except Exception as exc:
        emit(src_label(state["agent_name"]), "warning",
             "final report synthesis failed; using structured findings only",
             detail=str(exc))
        return ""
