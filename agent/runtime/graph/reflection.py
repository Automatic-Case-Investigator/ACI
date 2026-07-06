"""Model-driven self-review of a completed investigation task.

This replaces the six hand-authored re-injection guards that used to live in
`nodes_flow.assess` (triage-SIEM, investigation-SIEM, broad-query, depth, summary-format,
incomplete-pivot). Each of those encoded SOC reasoning as a Python `if` plus a bespoke
correction string and its own retry counter. They are collapsed here into one general
question the model answers once per task:

    "Given this task, the evidence I actually retrieved, and the report I wrote — am I
     genuinely DONE, or should I keep working? If keep working, what specifically next?"

The review returns BOTH:
  1. per-`## Findings` verdicts (confirmed / restated / speculative / ungrounded) — the
     same `FindingsVerification` the board-quality gate already consumes, so the pivot
     node's board gating is preserved unchanged; and
  2. an overall `conclude | keep_working` decision plus one targeted feedback string.

Deterministic signals (last search hit count, evidence-query count, unpivoted network
IOCs, missing report sections) are computed by the caller and passed in as grounding —
code does the deterministic measuring, the model does the semantic judgment.

Lives beside `findings_model` / `lead_model` (its siblings) so it can reuse them without
inverting the graph→analysis import direction. Mirrors their contract: one bounded async
model call, fail-open (returns None on unavailable/timeout/unparseable so the caller falls
back to a regex check and the run never stalls).
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass

from langchain_core.messages import HumanMessage, SystemMessage

from ..infra.logbus import emit, src_label

from .findings_model import FindingVerdict, FindingsVerification, _to_verdict
from .sanitize import _sanitize_message

_REVIEW_MODEL_TIMEOUT_SECS = 90

# Tolerant extraction of the first JSON object in a model response.
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

_REVIEW_SYSTEM = (
    "You are a senior SOC reviewer. An investigation agent has finished a task and "
    "written a report. Your job is to decide whether the task is genuinely DONE or "
    "needs MORE WORK, and to classify each '## Findings' bullet. You do NOT investigate "
    "or invent findings — you judge what the agent did against the evidence it retrieved.\n\n"
    "Use this general review method:\n"
    "1. Restate the task objective as the evidence question it must answer. When the task "
    "carries an explicit completion contract (success criteria), judge DONE against it: each "
    "criterion must be satisfied by named evidence, refuted, or explicitly recorded as an open "
    "gap — an activity performed is not an outcome achieved.\n"
    "2. Separate orientation/context from evidence retrieval. Prior board facts can support "
    "reasoning, but this task still needs its own evidence query unless it is purely a "
    "reporting/queue task.\n"
    "3. Ask whether the retrieved evidence was CAPABLE of answering the objective: correct "
    "entity, representation, behavior class, and time window; complete enough to read; and "
    "not merely a capped sample or aggregate pointer.\n"
    "4. Check whether every conclusion is grounded. A positive finding needs a retrieved "
    "event/artifact. A negative finding needs a complete, well-targeted search of the place "
    "the evidence would have appeared.\n"
    "5. Check investigation convergence. More work is justified only when it names a new "
    "representation, entity, window, or adjacent kill-chain step that is likely to reduce "
    "uncertainty. Repeating the same failed query shape is not convergence.\n"
    "6. Check pivot coverage. Newly confirmed artifacts should either have their relationship "
    "and adjacent-phase questions answered, be covered by a New Lead, or be explicitly recorded "
    "as exhausted.\n"
    "7. Preserve already-retrieved semantic evidence. Board artifacts and decoded payloads are "
    "evidence the agent already holds; a failed literal search does not refute them.\n\n"
    "Decide `keep_working` only when the next action is specific, evidence-seeking, and likely "
    "to improve the task. Otherwise choose `conclude`, even if some nonblocking case-wide gaps "
    "remain; those belong in hypotheses or New Leads. Do NOT demand more work when the agent "
    "has genuinely exhausted its angle: a thorough search that returns a real confirmed-negative "
    "is a complete task. Be concrete in `feedback`: name the specific next query, field, window, "
    "or pivot — not generic advice.\n\n"
    "Classify each '## Findings' bullet with exactly one status: `confirmed` (NEW fact "
    "backed by a retrieved event id / IOC), `restated` (true but already a board fact or a "
    "paraphrase of the alert), `speculative` (a 'may have' with no cited evidence), or "
    "`ungrounded` (cites an event id / IOC not in the retrieved evidence). Set `grounded` "
    "and `novel`; a finding is real only when confirmed AND grounded AND novel. When in "
    "doubt, do NOT mark confirmed."
)


@dataclass
class TaskReview:
    """Outcome of the per-task self-review.

    `findings` is the same `FindingsVerification` the board gate already consumes —
    serialized into `last_findings_verification` unchanged so the pivot node needs no
    edits. `decision` drives the single keep-working re-injection.
    """
    findings: FindingsVerification
    decision: str  # "conclude" | "keep_working"
    feedback_text: str

    @property
    def keep_working(self) -> bool:
        return self.decision == "keep_working"

    @property
    def verified_count(self) -> int:
        return self.findings.verified_count

    def to_feedback(self) -> str:
        """Agent-facing review block re-injected when the task must keep working.

        Combines the reviewer's concrete next-action note with the per-bullet rejection
        detail so the agent fixes the exact defects instead of guessing.
        """
        lines = ["Task review — keep working:"]
        if self.feedback_text:
            lines.append(self.feedback_text.strip())
        if self.findings.rejected:
            lines.append(self.findings.to_feedback())
        else:
            lines.append(f"You have {self.verified_count} verified finding(s).")
        return "\n\n".join(lines)

    def findings_state(self) -> dict:
        """Serializable findings verdicts for `AgentState.last_findings_verification`
        (identical shape to `FindingsVerification.to_state`, so board gating is unchanged)."""
        return self.findings.to_state()


def _build_review_prompt(
    *,
    findings_section: str,
    new_leads_section: str,
    evidence_digest: str,
    board_facts: list[str],
    current_task: dict | None,
    signals: dict,
    stop_condition: str = "",
) -> str:
    task_line = ""
    if current_task:
        task_line = f"Current task: {current_task.get('title') or ''}\n\n"
    # The completion contract the interpret loop derived for this task (its objective
    # decomposed into verifiable outcomes). The reviewer judges DONE against it.
    contract_line = ""
    if (stop_condition or "").strip():
        contract_line = (
            "## Task completion contract (success criteria the task set for itself)\n"
            f"{stop_condition.strip()}\n\n"
        )
    facts_block = "\n".join(f"- {f}" for f in board_facts) or "(none)"
    signal_lines = [
        f"- Real evidence queries this task: {signals.get('evidence_queries', 0)}",
    ]
    hit_count = signals.get("hit_count")
    if hit_count is not None:
        signal_lines.append(
            f"- Most recent search returned {hit_count:,} hits"
            + (" (AT/NEAR the result ceiling — likely truncated)"
               if signals.get("hit_ceiling") else "")
        )
    unpivoted = signals.get("unpivoted_iocs") or []
    if unpivoted:
        signal_lines.append(
            "- Confirmed network IOC(s) with no New Leads pivot: " + ", ".join(unpivoted)
        )
    clusters = signals.get("unqueried_clusters") or []
    if clusters:
        signal_lines.append(
            "- Post-peak activity window(s) PROFILED but never queried for raw events: "
            + ", ".join(clusters)
            + " — decide whether these unexamined windows are relevant to this task's objective."
        )
    time_gaps = signals.get("unqueried_time_ranges") or []
    if time_gaps:
        signal_lines.append(
            "- Time range(s) INSIDE a window the agent profiled but never searched for raw "
            "events: " + ", ".join(time_gaps)
            + " — use this as a coverage signal, then judge whether the gap could change "
            "the task conclusion."
        )
    unreported = signals.get("unreported_compromise_artifacts") or []
    if unreported:
        shown = [u if len(u) <= 140 else u[:140].rstrip() + "…" for u in unreported[:5]]
        signal_lines.append(
            "- CONFIRMED compromise indicator(s) on the board but MISSING from ## Findings: "
            + " | ".join(shown)
            + " — these are retrieved semantic artifacts the report should reconcile."
        )
    return (
        f"{task_line}"
        f"{contract_line}"
        "## Deterministic signals (measured by the harness — trust these)\n"
        + "\n".join(signal_lines)
        + "\n\n## '## Findings' bullets to classify (one verdict each, in order)\n"
        f"{findings_section or '(none)'}\n\n"
        "## '## New Leads' the agent proposed\n"
        f"{new_leads_section or '(none)'}\n\n"
        "## Evidence the task actually retrieved\n"
        f"{evidence_digest}\n\n"
        "## Facts already established on the board (treat repeats as `restated`)\n"
        f"{facts_block}\n\n"
        "Return ONLY a JSON object:\n"
        '{"findings": [{"text": "<bullet, trimmed>", '
        '"status": "confirmed|restated|speculative|ungrounded", '
        '"grounded": true, "novel": true, "event_refs": ["<event id>"], '
        '"reason": "<short reason; required when not confirmed>"}], '
        '"decision": "conclude|keep_working", '
        '"feedback": "<if keep_working: the specific next query/field/pivot; else brief>"}\n'
        "Skip '- None.' placeholder bullets in `findings`."
    )


def _parse_review(raw: str) -> dict | None:
    """Parse the model's JSON object. None signals unparseable (caller fails open)."""
    text = (raw or "").strip()
    if not text:
        return None
    match = _JSON_OBJECT_RE.search(text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _split_findings(data: dict) -> FindingsVerification:
    verified: list[FindingVerdict] = []
    rejected: list[FindingVerdict] = []
    for item in data.get("findings") or []:
        if not isinstance(item, dict):
            continue
        v = _to_verdict(item)
        if not v.text:
            continue
        (verified if v.is_verified else rejected).append(v)
    return FindingsVerification(verified=verified, rejected=rejected)


async def review_task_model(
    model,
    *,
    findings_section: str,
    new_leads_section: str,
    evidence_digest: str,
    board_facts: list[str],
    current_task: dict | None,
    agent_name: str,
    signals: dict,
    stop_condition: str = "",
) -> TaskReview | None:
    """Run the per-task self-review. Returns None on model failure (fail-open: the
    caller falls back to a regex completeness check and completes the task)."""
    src = src_label(agent_name)
    if model is None:
        emit(src, "warning", "task review: no model — falling back to regex check")
        return None

    prompt = _build_review_prompt(
        findings_section=findings_section,
        new_leads_section=new_leads_section,
        evidence_digest=evidence_digest,
        board_facts=board_facts,
        current_task=current_task,
        signals=signals,
        stop_condition=stop_condition,
    )
    try:
        resp = await asyncio.wait_for(
            model.ainvoke([
                SystemMessage(content=_REVIEW_SYSTEM),
                HumanMessage(content=prompt),
            ]),
            timeout=_REVIEW_MODEL_TIMEOUT_SECS,
        )
        _sanitize_message(resp)
        data = _parse_review(getattr(resp, "content", "") or "")
    except asyncio.TimeoutError:
        emit(src, "warning", f"task review: model timed out ({_REVIEW_MODEL_TIMEOUT_SECS}s) — falling back")
        return None
    except Exception as exc:
        emit(src, "warning", "task review: model call failed — falling back", detail=str(exc))
        return None

    if data is None:
        emit(src, "warning", "task review: unparseable response — falling back")
        return None

    decision = str(data.get("decision") or "").strip().lower()
    if decision not in {"conclude", "keep_working"}:
        # Unknown decision from a malformed verdict: default to conclude so the run is
        # never trapped in a keep-working loop on an unparseable signal.
        decision = "conclude"
    return TaskReview(
        findings=_split_findings(data),
        decision=decision,
        feedback_text=str(data.get("feedback") or "").strip(),
    )
