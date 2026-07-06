"""Cross-cutting helpers shared by the assess/pivot/completion nodes (preserved-findings, section extractors, run checkpoint)."""
from __future__ import annotations

from ....models import AgentRun
from ..parsing import _FACT_BULLET_RE, _FINDINGS_RE, _NEW_LEADS_HEADER_RE, _NEXT_HEADER_RE, _is_none_bullet, _normalize_fact_key, _strip_markers
from ..publication import extract_section as _extract_publication_section
from ..state import AgentState
from asgiref.sync import sync_to_async


async def _checkpoint_run(
    run_id: str,
    *,
    status: str | None = None,
    result: str | None = None,
    verdict: dict | None = None,
    phase: str | None = None,
) -> None:
    def _write() -> None:
        run = AgentRun.objects.filter(id=run_id).first()
        if run is None:
            return
        update_fields = ["updated_at"]
        if status is not None:
            run.status = status
            update_fields.append("status")
        if result is not None:
            run.result = result
            update_fields.append("result")
        if verdict is not None:
            run.verdict = verdict
            update_fields.append("verdict")
        if phase is not None:
            meta = dict(run.metadata or {})
            meta["graph_phase"] = phase
            if status in {AgentRun.STATUS_COMPLETED, AgentRun.STATUS_INCOMPLETE_BUDGET}:
                meta["terminal_candidate"] = True
            run.metadata = meta
            update_fields.append("metadata")
        run.save(update_fields=update_fields)

    try:
        await sync_to_async(_write, thread_sensitive=True)()
    except Exception:
        pass
def _findings_section_text(text: str) -> str:
    """Return the body of the ## Findings section, bounded by `_NEXT_HEADER_RE`.

    Not `_section_body`: the section-header regex consumes the trailing blank line, so a
    following `## Hypotheses` sits flush and `_section_body` would bleed Findings into it
    (the same reason `_missing_summary_sections` uses `_NEXT_HEADER_RE`).
    """
    text = text or ""
    match = _FINDINGS_RE.search(text)
    if not match:
        return ""
    rest = text[match.end():]
    next_header = _NEXT_HEADER_RE.search(rest)
    return (rest[:next_header.start()] if next_header else rest).strip()
def _new_leads_section_text(text: str) -> str:
    """Return the body of the ## New Leads section, bounded by `_NEXT_HEADER_RE`.

    Passed to the per-task self-review so it can check whether a confirmed network IOC
    was given a follow-up lead. Mirrors `_findings_section_text`.
    """
    text = text or ""
    match = _NEW_LEADS_HEADER_RE.search(text)
    if not match:
        return ""
    rest = text[match.end():]
    next_header = _NEXT_HEADER_RE.search(rest)
    return (rest[:next_header.start()] if next_header else rest).strip()
def _has_real_findings(text: str) -> bool:
    """True when the report's ## Findings section has at least one non-'None.' bullet.

    Fail-open fallback for the model-based self-review (see review_task_model).
    """
    for bullet in _FACT_BULLET_RE.finditer(_findings_section_text(text)):
        content, _ = _strip_markers(bullet.group(1).strip())
        if content and not _is_none_bullet(content):
            return True
    return False
def _coerce_preserved_findings(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        summary = " ".join(str(item.get("summary") or "").split())
        if not summary:
            continue
        event_ids = [
            " ".join(str(event_id).split())[:120]
            for event_id in (item.get("event_ids") or [])
            if str(event_id).strip()
        ][:8]
        out.append({
            "summary": summary[:900],
            "event_ids": event_ids,
            "source": ", ".join(event_ids),
        })
    return out[:12]
def _preserved_findings_from_state(state: AgentState) -> list[dict]:
    ledger = state.get("task_ledger") or {}
    return _coerce_preserved_findings(
        ledger.get("confirmed_findings") or state.get("last_confirmed_findings")
    )
def _finding_bullet(finding: dict) -> str:
    summary = str(finding.get("summary") or "").strip()
    event_ids = finding.get("event_ids") or []
    source = f" Event refs: {', '.join(event_ids[:6])}." if event_ids else ""
    return f"- {summary}{source}"
def _merge_preserved_findings(final_answer: str, findings: list[dict]) -> str:
    findings = _coerce_preserved_findings(findings)
    if not findings:
        return final_answer
    text = final_answer or ""
    bullets = [_finding_bullet(item) for item in findings]
    existing = _findings_section_text(text)
    existing_keys = {
        _normalize_fact_key(_strip_markers(match.group(1).strip())[0])
        for match in _FACT_BULLET_RE.finditer(existing)
    }
    missing = [
        bullet for bullet in bullets
        if _normalize_fact_key(_strip_markers(bullet[2:].strip())[0]) not in existing_keys
    ]
    if not missing:
        return text

    if not _FINDINGS_RE.search(text):
        return "## Findings\n" + "\n".join(missing) + "\n\n" + text.lstrip()

    match = _FINDINGS_RE.search(text)
    assert match is not None
    rest = text[match.end():]
    next_header = _NEXT_HEADER_RE.search(rest)
    body_end = match.end() + (next_header.start() if next_header else len(rest))
    current_body = text[match.end():body_end].strip()
    existing_real = [
        _strip_markers(item.group(1).strip())[0]
        for item in _FACT_BULLET_RE.finditer(current_body)
    ]
    existing_real = [item for item in existing_real if item and not _is_none_bullet(item)]
    body_lines = [f"- {item}" for item in existing_real] + missing
    new_body = "\n" + "\n".join(body_lines) + "\n\n"
    return text[:match.end()] + new_body + text[body_end:].lstrip()
def _extract_section(text: str, header: str) -> str:
    return _extract_publication_section(text, header)
