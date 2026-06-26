from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from typing import Iterable

from .parsing import _normalize_fact_key


_ARTIFACT_RE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|"
    r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b|"
    r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9_.-]+\b|"
    r"`([^`]+)`|"
    r"(?<!\w)/(?:[\w.+@=-]+/)+[\w.+@=-]+|"
    r"\b(?:host|user|account|srcip|dstip|ip|domain|hash|path|file|process|command)"
    r"\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)
_ISO_OR_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?\b"
)
_WORD_RE = re.compile(r"[a-z0-9]+")

_OBJECTIVE_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("initial_access", re.compile(r"\b(initial access|source ip|earliest|login|ssh|pam|session)\b", re.I)),
    ("c2_callback", re.compile(r"\b(c2|callback|/dev/tcp|listener|beacon|outbound|destination|10\.\d+\.\d+\.\d+)\b", re.I)),
    ("execution", re.compile(r"\b(exec|process|command|shell|payload|binary|script)\b", re.I)),
    ("persistence", re.compile(r"\b(persist|cron|crontab|scheduled task|startup|service)\b", re.I)),
    ("privilege_escalation", re.compile(r"\b(privilege|sudo|root|admin|escalat)\b", re.I)),
    ("lateral_movement", re.compile(r"\b(lateral|rdp|smb|winrm|ssh to|other host|second host)\b", re.I)),
    ("exfiltration", re.compile(r"\b(exfil|upload|download|transfer|egress|data)\b", re.I)),
    ("reporting", re.compile(r"\b(report|document|summari[sz]e|cleanup)\b", re.I)),
    ("scoping_enrichment", re.compile(r"\b(scope|enrich|reputation|ti|prevalence|baseline|correlate)\b", re.I)),
)


@dataclass(frozen=True)
class LeadCandidate:
    title: str
    pivots: str
    evidence: str
    priority: int
    original_index: int = 0


@dataclass(frozen=True)
class LeadDecision:
    candidate: LeadCandidate
    approved: bool
    reason: str
    category: str
    score: int
    signature: str


@dataclass(frozen=True)
class LeadValidationResult:
    approved: list[LeadDecision]
    rejected: list[LeadDecision]
    deferred: list[LeadDecision]

    def counts(self) -> dict[str, int]:
        out = {"approved": len(self.approved), "deferred": len(self.deferred)}
        for decision in self.rejected:
            out[decision.category] = out.get(decision.category, 0) + 1
        return out

    def detail(self) -> str:
        rows = []
        for decision in [*self.approved, *self.deferred, *self.rejected]:
            rows.append({
                "title": decision.candidate.title,
                "approved": decision.approved,
                "category": decision.category,
                "reason": decision.reason,
                "score": decision.score,
                "signature": decision.signature,
            })
        return json.dumps(rows, indent=2, ensure_ascii=False)


def coerce_lead_candidates(raw_leads: Iterable) -> list[LeadCandidate]:
    candidates: list[LeadCandidate] = []
    for idx, item in enumerate(raw_leads):
        if isinstance(item, LeadCandidate):
            candidates.append(item)
            continue
        title = pivots = evidence = ""
        priority = 50
        if isinstance(item, dict):
            title = str(item.get("title") or "")
            pivots = str(item.get("pivots") or "")
            evidence = str(item.get("evidence") or "")
            priority = _safe_priority(item.get("priority"))
        elif isinstance(item, (tuple, list)):
            if len(item) >= 4:
                title, pivots, evidence, priority = item[:4]
            elif len(item) >= 3:
                title, pivots, priority = item[:3]
            title = str(title or "")
            pivots = str(pivots or "")
            evidence = str(evidence or "")
            priority = _safe_priority(priority)
        candidates.append(LeadCandidate(
            title=title.strip(),
            pivots=pivots.strip(),
            evidence=evidence.strip(),
            priority=priority,
            original_index=idx,
        ))
    return candidates


# Kill-chain direction of a lead, keyed off the objective prefix baked into its
# signature. Used to guarantee both an upstream (root-cause) and downstream
# (impact) lead survive the budget gate instead of one direction taking every slot.
_BACKWARD_OBJECTIVES = frozenset({"initial_access", "privilege_escalation"})
_FORWARD_OBJECTIVES = frozenset(
    {"c2_callback", "execution", "persistence", "lateral_movement", "exfiltration"}
)


def _lead_direction(decision: LeadDecision) -> str:
    objective = decision.signature.split(":", 1)[0]
    if objective in _BACKWARD_OBJECTIVES:
        return "backward"
    if objective in _FORWARD_OBJECTIVES:
        return "forward"
    return "neutral"


def apply_lead_budget(
    approved_pool: list[LeadDecision],
    *,
    max_approved: int | None = None,
    remaining_run_budget: int | None = None,
) -> tuple[list[LeadDecision], list[LeadDecision]]:
    """Return model-approved leads in deterministic priority order.

    Lead budgets are disabled. The optional cap arguments remain only for call
    compatibility with older code/tests and are intentionally ignored.
    """
    ordered = sorted(
        approved_pool,
        key=lambda d: (-d.score, -d.candidate.priority, d.candidate.original_index),
    )
    return ordered, []


def _safe_priority(value) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 50


def _objective_bucket(text: str) -> str:
    for name, pattern in _OBJECTIVE_PATTERNS:
        if pattern.search(text or ""):
            return name
    return "scoping_enrichment"


def _artifacts(text: str) -> frozenset[str]:
    out: set[str] = set()
    for match in _ARTIFACT_RE.finditer(text or ""):
        value = next((g for g in match.groups() if g), match.group(0))
        cleaned = value.strip("`'\".,;()[]{}").lower()
        if cleaned and len(cleaned) > 1:
            out.add(cleaned)
    # ISO timestamps deliberately excluded from artifact sets.
    # Including them causes the same investigative question to produce a unique
    # signature on each pivot round (each SIEM query surfaces different timestamps),
    # defeating deduplication and making the investigation non-convergent.
    return frozenset(out)


def _signature(objective: str, artifacts: frozenset[str], pivots: str, title: str) -> str:
    pivot_key = _normalize_fact_key(pivots)
    if artifacts:
        return objective + ":" + ",".join(sorted(artifacts))
    return objective + ":" + (pivot_key or _normalize_fact_key(title))


def lead_signature(candidate: LeadCandidate) -> str:
    """Stable dedup signature for a candidate (objective + artifacts/pivots)."""
    text = " ".join([candidate.title, candidate.pivots, candidate.evidence]).strip()
    objective = _objective_bucket(text)
    return _signature(objective, _artifacts(text), candidate.pivots, candidate.title)


def _task_ref(task: dict) -> dict:
    title = str(task.get("title") or "")
    description = str(task.get("description") or "")
    summary = str(task.get("summary") or "")
    text = " ".join([title, description, summary])
    # Objective comes from title+description only — the summary may mention artifacts
    # from other kill-chain phases (e.g. "reverse shell" in findings text) and would
    # drag the task into the wrong bucket, breaking dedup signature matching.
    objective = _objective_bucket(" ".join([title, description]))
    artifacts = _artifacts(text)
    status = str(task.get("status") or "").strip().lower()
    summary = str(task.get("summary") or "")
    conclusion = str(task.get("conclusion") or "")
    return {
        "title": str(task.get("title") or ""),
        "text": text,
        "norm_title": _normalize_fact_key(str(task.get("title") or "")),
        "objective": objective,
        "artifacts": artifacts,
        "status": status,
        "summary": summary,
        "conclusion": conclusion,
        "blocks_duplicate": _task_blocks_duplicate(status, summary, conclusion),
        "signature": _signature(objective, artifacts, str(task.get("description") or ""), str(task.get("title") or "")),
    }


def _task_blocks_duplicate(status: str, summary: str, conclusion: str) -> bool:
    """Whether an existing task should suppress a follow-up lead as duplicate.

    Active queued work still blocks exact duplicate efforts. Completed work only
    blocks when it appears to have reached a firm conclusion; inconclusive or
    still-open outcomes should not suppress a new lead.
    """
    normalized_status = (status or "").strip().lower()
    if normalized_status in {"pending", "claimed", "running", "in_progress"}:
        return True
    if normalized_status not in {"completed"}:
        return False

    outcome = "\n".join(filter(None, [summary, conclusion])).lower()
    if not outcome.strip():
        return False

    unresolved_markers = (
        "[open]",
        "open question",
        "open gap",
        "still unknown",
        "remains unknown",
        "remains open",
        "not confirmed",
        "did not confirm",
        "did not find",
        "did not retrieve",
        "no direct evidence",
        "no evidence",
        "no results",
        "no matching",
        "no events found",
        "no telemetry",
        "nothing found",
        "not found",
        "zero events",
        "could not confirm",
        "could not establish",
        "could not be confirmed",
        "could not be established",
        "cannot confirm",
        "cannot be confirmed",
        "insufficient data",
        "inconclusive",
        "unconfirmed",
        "uncertain",
        "unknown",
        "not proven",
        "not established",
        "not fully reconstructed",
        "has not been demonstrated",
        "may have occurred",
        "may still exist",
    )
    return not any(marker in outcome for marker in unresolved_markers)


def duplicate_existing_task(candidate: LeadCandidate, existing_refs: list[dict]) -> str:
    """Deterministic backstop for the model's duplicate check: flag a candidate
    that matches an already-queued task by signature, objective+artifact, or
    title similarity. Returns the reason, or '' if not a duplicate."""
    text = " ".join([candidate.title, candidate.pivots, candidate.evidence]).strip()
    objective = _objective_bucket(text)
    artifacts = _artifacts(text)
    signature = _signature(objective, artifacts, candidate.pivots, candidate.title)
    title_key = _normalize_fact_key(candidate.title)
    for ref in existing_refs:
        if not ref.get("blocks_duplicate"):
            continue
        is_active = ref.get("status") in {"pending", "claimed", "running", "in_progress"}
        label = "active task" if is_active else "resolved task"
        if ref["signature"] == signature:
            return f"duplicate of {label}: {ref['title']}"
        if objective == ref["objective"] and artifacts and artifacts & ref["artifacts"]:
            return f"same objective and artifact as {label}: {ref['title']}"
        if title_key and _title_similarity(title_key, ref["norm_title"]) >= 0.78:
            return f"semantically similar to {label}: {ref['title']}"
    return ""


def _title_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    left_words = set(_WORD_RE.findall(left))
    right_words = set(_WORD_RE.findall(right))
    if not left_words or not right_words:
        return 0.0
    jaccard = len(left_words & right_words) / len(left_words | right_words)
    return max(jaccard, difflib.SequenceMatcher(None, left, right).ratio())
