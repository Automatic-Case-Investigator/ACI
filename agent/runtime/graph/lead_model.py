from __future__ import annotations

import asyncio
import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from ..infra.logbus import emit, src_label

from .leads import (
    LeadCandidate,
    LeadDecision,
    LeadValidationResult,
    _safe_priority,
    _task_ref,
    apply_lead_budget,
    duplicate_existing_task,
    lead_signature,
)
from .sanitize import _sanitize_message

_LEAD_MODEL_TIMEOUT_SECS = 90

_VALID_CATEGORIES = {"approved", "invalid", "duplicate", "low_relevance"}

_LEAD_SYSTEM = (
    "You are a SOC investigation lead reviewer. You read an analyst's report plus a "
    "free-form '## New Leads' section and turn them into a clean, validated list of "
    "follow-up investigation leads. The analyst's formatting is inconsistent — leads "
    "may span multiple lines, use sub-bullets, capitalize field names differently, or "
    "be written as prose. Reassemble each lead into ONE whole candidate; never split "
    "a single lead's title/pivots/evidence into separate leads. A real incident leaves "
    "threads open in BOTH directions of the kill chain, and you should spawn leads for "
    "both when they are unconfirmed:\n"
    "- BACKWARD (upstream / root cause): how the actor reached the confirmed activity — "
    "initial access vector, source IP of the first login/session, how the account or "
    "sudo/privilege was obtained, earlier reconnaissance or staging.\n"
    "- FORWARD (downstream / impact): what the actor did or does next — C2/callback "
    "confirmation, lateral movement, data access/exfiltration, additional persistence, "
    "post-exploitation commands after the confirmed event.\n"
    "Bias toward action, but never re-run finished work: reject a lead when it is "
    "genuinely empty/vague, or would repeat a queued OR completed task. Be decisive."
)

# Tolerant extraction of the first JSON array in a model response.
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


def _build_prompt(
    leads_section: str,
    final_answer: str,
    existing_tasks: list[dict],
    current_task: dict | None,
) -> str:
    # Include status so the model can tell pending from already-completed work and
    # never re-open a finished task.
    existing = "\n".join(
        f"- [{t.get('status', '?')}] {t.get('title', '')}" for t in (existing_tasks or [])
    ) or "- (none)"
    task_line = ""
    if current_task:
        task_line = (
            f"\n## Task just completed\n{current_task.get('title') or ''}\n"
            f"{current_task.get('description') or ''}\n"
        )
    return (
        f"## Analyst report (for context)\n{(final_answer or '').strip()[:6000]}\n"
        f"{task_line}\n"
        f"## Already-queued / completed investigation tasks\n{existing}\n\n"
        f"## Proposed New Leads section to validate\n{(leads_section or '').strip()[:6000]}\n\n"
        "Extract and validate leads. Return ONLY a JSON array (no prose, no code "
        "fences). Each element:\n"
        "{\n"
        '  "title": str,            // concise imperative lead title\n'
        '  "pivots": str,           // concrete pivots: host/user/ip/path/time window/rule ids\n'
        '  "evidence": str,         // the evidence anchor that motivates the lead\n'
        '  "priority": int,         // 0-100\n'
        '  "approved": bool,\n'
        '  "category": "approved"|"invalid"|"duplicate"|"low_relevance",\n'
        '  "reason": str            // one short clause justifying the decision\n'
        "}\n\n"
        "Extraction + generation:\n"
        "- Reassemble every lead in the New Leads section into one whole candidate.\n"
        "- ALSO derive leads from unconfirmed threads in the report, covering BOTH a "
        "BACKWARD angle (initial access / source IP / how privilege was obtained) and a "
        "FORWARD angle (C2 confirmation / lateral movement / exfil / extra persistence). "
        "Anything under Open Gaps is a strong candidate.\n\n"
        "Validation rules:\n"
        "- REJECT as 'invalid' only a lead with no real title or a placeholder/no-op.\n"
        "- REJECT as 'low_relevance' only a vague lead with no concrete artifact.\n"
        "- REJECT as 'duplicate' when the lead would re-run essentially the same "
        "query/scope as a task listed above — INCLUDING tasks marked [completed]; do "
        "not re-open finished work. Sharing a host/IP/path/time-window is NOT enough — "
        "a different angle (upstream cause vs downstream impact) is a NEW lead.\n"
        "- Otherwise set approved=true. When in doubt about a genuinely new angle, "
        "approve.\n"
        "- Always fill title/pivots/evidence with the reassembled content even when "
        "rejecting, so the decision is auditable.\n"
        "Return [] only if there are genuinely no real leads in either direction."
    )


def _parse_model_leads(raw: str) -> list[dict]:
    text = (raw or "").strip()
    if not text:
        return []
    match = _JSON_ARRAY_RE.search(text)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def _to_decision(item: dict, index: int, existing_refs: list[dict]) -> LeadDecision:
    candidate = LeadCandidate(
        title=str(item.get("title") or "").strip(),
        pivots=str(item.get("pivots") or "").strip(),
        evidence=str(item.get("evidence") or "").strip(),
        priority=_safe_priority(item.get("priority")),
        original_index=index,
    )
    signature = lead_signature(candidate)
    category = str(item.get("category") or "").strip().lower()
    approved = bool(item.get("approved")) and category in {"approved", ""}
    reason = str(item.get("reason") or "").strip() or ("approved" if approved else "rejected by reviewer")
    if not candidate.title:
        approved, category, reason = False, "invalid", "empty lead title"
    elif category not in _VALID_CATEGORIES:
        category = "approved" if approved else "low_relevance"
    if approved:
        # Deterministic backstop: never queue a duplicate of an existing task even
        # if the model missed it.
        dup = duplicate_existing_task(candidate, existing_refs)
        if dup:
            approved, category, reason = False, "duplicate", dup
    score = candidate.priority + (10 if approved else 0)
    return LeadDecision(candidate, approved, reason, category or "approved", score, signature)


async def validate_leads_model(
    model,
    *,
    leads_section: str,
    final_answer: str,
    existing_tasks: list[dict],
    current_task: dict | None,
    remaining_run_budget: int | None,
    agent_name: str,
) -> LeadValidationResult:
    """Model-based lead extraction + validation. Fails closed (empty result) when
    the model is unavailable or the call fails, so a bad/missing model never
    silently mis-parses leads — it just produces none, loudly."""
    src = src_label(agent_name)
    empty = LeadValidationResult(approved=[], rejected=[], deferred=[])
    if model is None:
        emit(src, "warning", "lead validator: no model available — skipping lead creation this turn")
        return empty
    if not (leads_section or "").strip():
        return empty

    existing_refs = [_task_ref(t) for t in existing_tasks]
    prompt = _build_prompt(leads_section, final_answer, existing_tasks, current_task)

    try:
        resp = await asyncio.wait_for(
            model.ainvoke([
                SystemMessage(content=_LEAD_SYSTEM),
                HumanMessage(content=prompt),
            ]),
            timeout=_LEAD_MODEL_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        items = _parse_model_leads(getattr(resp, "content", "") or "")
    except asyncio.TimeoutError:
        emit(src, "warning", f"lead validator: model timed out ({_LEAD_MODEL_TIMEOUT_SECS}s) — no leads created")
        return empty
    except Exception as exc:
        emit(src, "warning", "lead validator: model call failed — no leads created", detail=str(exc))
        return empty

    if not items:
        return empty

    approved_pool: list[LeadDecision] = []
    rejected: list[LeadDecision] = []
    seen_signatures: set[str] = set()
    for index, item in enumerate(items):
        decision = _to_decision(item, index, existing_refs)
        if decision.approved:
            if decision.signature in seen_signatures:
                rejected.append(LeadDecision(
                    decision.candidate, False, "duplicate of another proposed lead",
                    "duplicate", decision.score, decision.signature,
                ))
                continue
            seen_signatures.add(decision.signature)
            approved_pool.append(decision)
        else:
            rejected.append(decision)

    approved, deferred = apply_lead_budget(approved_pool, remaining_run_budget=remaining_run_budget)
    return LeadValidationResult(approved=approved, rejected=rejected, deferred=deferred)
