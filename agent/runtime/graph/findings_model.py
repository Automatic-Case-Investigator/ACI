"""Model-based verification of an investigation task's ## Findings.

The depth guard used to decide "did this task actually find something?" with a regex
(`_has_real_findings` — is there a non-`None.` bullet?). That is fooled by a bullet
that merely restates the alert or cites an event that was never retrieved, letting the
agent quit early on a non-finding and polluting the board with it.

This module classifies each ## Findings bullet with the model — confirmed / restated /
speculative / ungrounded — against the task's actual evidence and the existing board.
The result drives three things (see nodes_flow):
  1. the depth guard's "keep digging" decision (verified_count, not bullet count),
  2. board-quality gating (only `confirmed` bullets become board facts), and
  3. detailed per-bullet feedback re-injected to the agent so it fixes the exact defects.

Mirrors `lead_model.validate_leads_model`: one bounded async model call, fail-open
(returns None on unavailable/timeout/unparseable so callers fall back to the regex).
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ..infra.logbus import emit, src_label

from .parsing import _JSON_EVENT_ID_RE
from .sanitize import _sanitize_message

_FINDINGS_MODEL_TIMEOUT_SECS = 90
_VALID_STATUSES = {"confirmed", "restated", "speculative", "ungrounded"}
_MAX_DIGEST_EVENT_IDS = 60
_MAX_BOARD_FACTS = 40

# Tolerant extraction of the first JSON array in a model response.
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)

_FINDINGS_SYSTEM = (
    "You are a SOC findings verifier. You read an investigation task's '## Findings' "
    "bullets and classify each one against the evidence the task actually retrieved "
    "and the facts already on the investigation board. You do NOT investigate or invent "
    "findings — you only judge the bullets given.\n\n"
    "Classify each bullet with exactly one status:\n"
    "- `confirmed`: a NEW, concrete fact backed by an event id / IOC that appears in the "
    "EVIDENCE the task retrieved. This is a genuine finding.\n"
    "- `restated`: true but already an established board fact or a paraphrase of the "
    "alert/triage context — not new work.\n"
    "- `speculative`: a claim, hypothesis, or 'may have' with no cited event id / IOC.\n"
    "- `ungrounded`: cites an event id / IOC that is NOT present in the retrieved "
    "evidence (unsupported — possibly fabricated).\n\n"
    "Also set `grounded` (true only when the bullet's citation is present in the "
    "evidence) and `novel` (true only when it is not already a board fact). A finding "
    "counts as real only when status=confirmed AND grounded AND novel.\n"
    "Be strict: when in doubt between confirmed and restated/speculative, do NOT mark "
    "confirmed. Give a short `reason` for every non-confirmed bullet so the analyst can "
    "fix it."
)


@dataclass(frozen=True)
class FindingVerdict:
    text: str
    status: str
    grounded: bool
    novel: bool
    reason: str
    event_refs: list = field(default_factory=list)

    @property
    def is_verified(self) -> bool:
        return self.status == "confirmed" and self.grounded and self.novel

    def to_dict(self) -> dict:
        return {
            "text": self.text, "status": self.status, "grounded": self.grounded,
            "novel": self.novel, "reason": self.reason, "event_refs": list(self.event_refs),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FindingVerdict":
        return cls(
            text=str(d.get("text") or "").strip(),
            status=str(d.get("status") or "").strip().lower(),
            grounded=bool(d.get("grounded")),
            novel=bool(d.get("novel")),
            reason=str(d.get("reason") or "").strip(),
            event_refs=list(d.get("event_refs") or []),
        )


@dataclass
class FindingsVerification:
    verified: list[FindingVerdict]
    rejected: list[FindingVerdict]

    @property
    def verified_count(self) -> int:
        return len(self.verified)

    def to_feedback(self, max_items: int = 5) -> str:
        """Agent-facing review block listing the rejected bullets and why.

        Re-injected into the loop so the agent fixes the specific defects instead of
        guessing. Bounded so it never floods context.
        """
        total = len(self.verified) + len(self.rejected)
        lines = [
            f"Findings review ({len(self.rejected)} of {total} bullet(s) rejected; "
            f"{self.verified_count} verified):"
        ]
        for v in self.rejected[:max_items]:
            text = v.text if len(v.text) <= 100 else v.text[:100].rstrip() + "…"
            reason = v.reason if len(v.reason) <= 120 else v.reason[:120].rstrip() + "…"
            lines.append(f'- REJECTED [{v.status or "?"}] "{text}" -> {reason}')
        if len(self.rejected) > max_items:
            lines.append(f"- … {len(self.rejected) - max_items} more rejected bullet(s)")
        lines.append(f"You have {self.verified_count} verified finding(s).")
        return "\n".join(lines)

    def to_state(self) -> dict:
        """Serializable form carried on AgentState for reuse in the pivot node."""
        return {
            "verified": [v.to_dict() for v in self.verified],
            "rejected": [v.to_dict() for v in self.rejected],
        }

    @classmethod
    def from_state(cls, data: dict | None) -> "FindingsVerification | None":
        if not isinstance(data, dict):
            return None
        return cls(
            verified=[FindingVerdict.from_dict(d) for d in data.get("verified") or []],
            rejected=[FindingVerdict.from_dict(d) for d in data.get("rejected") or []],
        )


def build_evidence_digest(state, messages: list) -> tuple[str, list[str]]:
    """Assemble the evidence corpus the verifier judges against.

    Returns (digest_text, board_facts). The digest carries the event ids and trusted
    artifact literals actually retrieved this task; board_facts are existing confirmed
    facts so the model can flag restatements. Reuses the grounding helpers so the
    verifier shares one notion of "trusted evidence" with the literal-grounding guard.
    """
    from .validation import _board_entries_for_validation, _trusted_artifacts_for_validation

    event_ids: list[str] = []
    seen: set[str] = set()
    for msg in messages or []:
        if isinstance(msg, ToolMessage):
            for eid in _JSON_EVENT_ID_RE.findall(getattr(msg, "content", "") or ""):
                if eid not in seen:
                    seen.add(eid)
                    event_ids.append(eid)
                if len(event_ids) >= _MAX_DIGEST_EVENT_IDS:
                    break

    artifacts = sorted(_trusted_artifacts_for_validation(state, messages))
    board_facts = [
        str(e.get("content") or "").strip()
        for e in _board_entries_for_validation(state)
        if e.get("kind") == "fact" and str(e.get("content") or "").strip()
    ][:_MAX_BOARD_FACTS]

    digest = (
        "Event ids retrieved this task: "
        + (", ".join(event_ids) if event_ids else "(none)")
        + "\nTrusted artifacts/IOCs in retrieved evidence: "
        + (", ".join(artifacts) if artifacts else "(none)")
    )
    return digest, board_facts


def _build_findings_prompt(findings_section: str, evidence_digest: str,
                           board_facts: list[str], current_task: dict | None) -> str:
    task_line = ""
    if current_task:
        task_line = f"Current task: {current_task.get('title') or ''}\n\n"
    facts_block = "\n".join(f"- {f}" for f in board_facts) or "(none)"
    return (
        f"{task_line}"
        "## Findings bullets to verify (one verdict each, in order):\n"
        f"{findings_section}\n\n"
        "## Evidence the task actually retrieved\n"
        f"{evidence_digest}\n\n"
        "## Facts already established on the board (treat repeats as `restated`)\n"
        f"{facts_block}\n\n"
        "Return ONLY a JSON array, one object per ## Findings bullet, in order:\n"
        '[{"text": "<the bullet, trimmed>", '
        '"status": "confirmed|restated|speculative|ungrounded", '
        '"grounded": true, "novel": true, "event_refs": ["<event id cited>"], '
        '"reason": "<short reason; required when not confirmed>"}]\n'
        "Skip '- None.' placeholder bullets entirely. Return [] if there are no real bullets."
    )


def _parse_model_verdicts(raw: str) -> list[dict] | None:
    """Parse the model's JSON array. None signals unparseable (caller fails open);
    [] is a valid 'no real bullets' answer."""
    text = (raw or "").strip()
    if not text:
        return None
    match = _JSON_ARRAY_RE.search(text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return [d for d in data if isinstance(d, dict)]


def _to_verdict(item: dict) -> FindingVerdict:
    v = FindingVerdict.from_dict(item)
    if v.status not in _VALID_STATUSES:
        # Unknown status is treated as not-a-finding so it can never pass as verified.
        v = FindingVerdict(v.text, "speculative", False, v.novel,
                           v.reason or "unrecognized status from verifier", v.event_refs)
    return v


async def verify_findings_model(
    model,
    *,
    findings_section: str,
    evidence_digest: str,
    board_facts: list[str],
    current_task: dict | None,
    agent_name: str,
) -> FindingsVerification | None:
    """Classify each ## Findings bullet. Returns None on model failure (fail-open:
    the caller falls back to the regex `_has_real_findings`). An empty findings
    section returns an empty (valid) verification, not None."""
    src = src_label(agent_name)
    if model is None:
        emit(src, "warning", "findings verifier: no model — falling back to regex check")
        return None
    if not (findings_section or "").strip():
        return FindingsVerification(verified=[], rejected=[])

    prompt = _build_findings_prompt(findings_section, evidence_digest, board_facts, current_task)
    try:
        resp = await asyncio.wait_for(
            model.ainvoke([
                SystemMessage(content=_FINDINGS_SYSTEM),
                HumanMessage(content=prompt),
            ]),
            timeout=_FINDINGS_MODEL_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        items = _parse_model_verdicts(getattr(resp, "content", "") or "")
    except asyncio.TimeoutError:
        emit(src, "warning", f"findings verifier: model timed out ({_FINDINGS_MODEL_TIMEOUT_SECS}s) — falling back")
        return None
    except Exception as exc:
        emit(src, "warning", "findings verifier: model call failed — falling back", detail=str(exc))
        return None

    if items is None:
        emit(src, "warning", "findings verifier: unparseable response — falling back")
        return None

    verified: list[FindingVerdict] = []
    rejected: list[FindingVerdict] = []
    for item in items:
        v = _to_verdict(item)
        if not v.text:
            continue
        (verified if v.is_verified else rejected).append(v)
    return FindingsVerification(verified=verified, rejected=rejected)
