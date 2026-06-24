from __future__ import annotations

import json

from .parsing import _FACT_BULLET_RE, _HYPOTHESES_RE, _is_none_bullet, _looks_like_lead, _normalize_fact_key, _section_body, _strip_markers
from .state import AgentState
from .toolio import _is_error_tool_result



def _format_board_context(raw: str) -> str:
    """Format a get_board JSON response as a compact board context string."""
    if not raw or _is_error_tool_result(raw):
        return ""
    try:
        data = json.loads(raw)
        entries = data.get("entries", []) if isinstance(data, dict) else []
    except Exception:
        return ""
    if not entries:
        return ""

    artifacts = [e for e in entries if e.get("kind") == "artifact"]
    facts = [e for e in entries if e.get("kind") == "fact"]
    hyps = [e for e in entries if e.get("kind") == "hypothesis"]
    ti_results = [e for e in entries if e.get("kind") == "ti_result"]
    lines = [
        "\n\n---",
        "**Findings Board (use this state in the current task):**",
    ]
    if artifacts:
        lines.append("*Found artifacts — use these as pivots where relevant:*")
        for e in artifacts:
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- {e['content']}{src}")
    if facts:
        lines.append("*Confirmed facts — treat as established unless contradicted by newer evidence:*")
        for e in facts:
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- {e['content']}{src}")
    if hyps:
        lines.append(
            "*Hypotheses — when one becomes confirmed or refuted, restate it in your "
            "`## Hypotheses` section prefixed with `[Confirmed]` or `[Refuted]` (same "
            "wording); the board reconciles its status automatically:*"
        )
        for e in hyps:
            status = e.get("status", "open")
            conf = e.get("confidence", "")
            src = f" [{e['source']}]" if e.get("source") else ""
            lines.append(f"- [{status}/{conf}] {e['content']}{src}")
    if ti_results:
        lines.append(
            "*TI Enrichment — advisory only; verify against SIEM before treating as fact:*"
        )
        for e in ti_results:
            ref = f" <{e['source']}>" if e.get("source") else ""
            lines.append(f"- {e['content']}{ref}")
    lines.append(
        "Use the Findings Board actively: pivot on relevant artifacts, build on confirmed "
        "facts, and report how the current work changes each applicable hypothesis."
    )
    lines.append("---")
    return "\n".join(lines)


def _record_board_entry(
    state: AgentState,
    *,
    kind: str,
    content: str,
    source: str = "",
    confidence: str = "medium",
    status: str = "open",
    dedup_key: str | None = None,
) -> None:
    from aci_board import store

    store.init_db()
    store.add_entry(
        case_id=state["case_id"],
        run_id=state["run_id"],
        agent_name=state["agent_name"],
        kind=kind,
        content=content,
        source=source,
        confidence=confidence,
        status=status,
        dedup_key=dedup_key,
    )


def _record_hypotheses_text(
    state: AgentState,
    text: str,
    *,
    source: str = "",
) -> int:
    """Persist `## Hypotheses` bullets as upserts.

    A bullet may carry leading markers (`**bold**`, `[id=..]`, `[Refuted]`,
    `[Confirmed]`, `[Open]`). When the cleaned content matches an existing
    hypothesis (ignoring those markers and volatile event ids/timestamps), update
    that entry's status instead of adding a duplicate row. Questions/imperatives
    (leads) are skipped.
    """
    match = _HYPOTHESES_RE.search(text or "")
    if not match:
        return 0
    block = _section_body(text, match)

    from aci_board import store
    store.init_db()
    existing = [
        e for e in store.list_entries(
            state["case_id"], state["run_id"], state["agent_name"]
        ) if e.get("kind") == "hypothesis"
    ]
    by_key = {(e.get("dedup_key") or "").strip().lower(): e for e in existing}

    created = 0
    for bullet in _FACT_BULLET_RE.finditer(block):
        raw = bullet.group(1).strip()
        content, status = _strip_markers(raw)
        if not content or _is_none_bullet(content):
            continue
        if _looks_like_lead(content):
            # A question/imperative is a lead, not a hypothesis.
            continue
        key = _normalize_fact_key(content)
        match_entry = by_key.get(key)
        if match_entry:
            # Only transition status when the bullet declares one.
            if status and match_entry.get("status") != status:
                store.update_entry(match_entry["id"], status=status, content=content)
            continue
        new_entry = store.add_entry(
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
            kind="hypothesis",
            content=content,
            source=source,
            confidence="medium",
            status=status or "open",
            dedup_key=key,
        )
        by_key[key] = new_entry
        created += 1
    return created


def _entry_line(e: dict) -> str:
    content = (e.get("content") or "").strip()
    src = f" [{e['source']}]" if e.get("source") else ""
    status = e.get("status")
    tag = f"[{status}] " if status and status not in ("observed",) else ""
    return f"- {tag}{content}{src}"
