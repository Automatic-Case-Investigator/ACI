from __future__ import annotations

import re

from ..infra.avfs import reports_dir


def extract_section(text: str, header: str) -> str:
    """Return the body of a `## <header>` section from a report, or '' if absent."""
    pattern = re.compile(
        rf"^#{{1,3}}\s*{re.escape(header)}\s*$\n(.*?)(?=^#{{1,3}}\s|\Z)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text or "")
    return m.group(1).strip() if m else ""


def build_session_note(state: dict, verdict: dict | None, final_answer: str) -> str:
    """Compose a `/sessions` handoff note so the next run can resume from prior work."""
    v = verdict or {}
    case_id = state.get("case_id", "?")
    lines = [
        f"# Session handoff - case {case_id}",
        "",
        f"- Run: `{state.get('run_id', '?')}`  -  status: `{state.get('status', '?')}`",
    ]
    if v:
        verdict_label = str(v.get("verdict", "?")).upper()
        triage = str(v.get("triage_verdict", "") or "").upper()
        triage_suffix = f" (triage was {triage})" if triage and triage != verdict_label else ""
        lines.append(
            f"- Verdict: **{verdict_label}** ({v.get('confidence', '?')}); "
            f"impact={v.get('impact_state', '?')}, scope={v.get('scope_state', '?')}{triage_suffix}"
        )

    summary = extract_section(final_answer, "Executive Summary") or extract_section(final_answer, "Verdict")
    if summary:
        lines += ["", "## What this run concluded", summary[:1200]]

    gaps = list(v.get("blocking_gaps") or []) + list(v.get("nonblocking_gaps") or [])
    if gaps:
        lines += ["", "## Open gaps / pending"] + [f"- {g}" for g in gaps[:10]]

    next_steps = []
    if v.get("recommended_action"):
        next_steps.append(v["recommended_action"])
    open_gaps_section = extract_section(final_answer, "Open Gaps")
    if open_gaps_section:
        next_steps.append(open_gaps_section[:600])
    if next_steps:
        lines += ["", "## Next-session priorities"] + [f"- {s}" for s in next_steps]

    lines += ["", f"_Full report: `{reports_dir(case_id)}/final.md`_"]
    return "\n".join(lines)
