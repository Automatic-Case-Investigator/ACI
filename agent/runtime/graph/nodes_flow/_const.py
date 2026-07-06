"""Shared module-level constants for the nodes_flow package (regexes, caps, timeouts)."""
from __future__ import annotations

from datetime import timedelta
import re


_VERDICT_REPAIR_TIMEOUT_SECS = 45
# How many times the assess node re-injects a "keep working" / "fix the report" nudge
# from the per-task self-review before accepting the best-effort answer, so the run never
# stalls on a model that cannot satisfy the review. One unified cap replaces the four
# per-guard retry counters the cascade used to carry. Used by the triage SIEM guard and
# the investigation zero-evidence floor (both fire at most once at retry 0).
_MAX_REFLECTION_RETRIES = 2
# Investigation keep-working is PROGRESS-gated, not capped at a flat count: the task keeps
# gathering as long as each nudge produces new evidence and effort/global budget remain
# (a productive task goes deeper; a stalled one concludes at once). This is a rarely-hit
# hard safety backstop so a pathological loop cannot run forever; the effort ceiling and
# the run-level budget are the real bounds.
_MAX_INVESTIGATION_RETRIES = 8
# Search tools whose result hit count signals query specificity.
_SEARCH_RESULT_TOOLS = frozenset({"search", "search_keyword"})
# Distinct evidence queries after which a task with no verified finding is treated as a
# genuine confirmed-negative and allowed to conclude (bounds the keep-working loop on a
# truly empty angle). The per-task cap (_MAX_TASK_TOOL_CALLS) is the hard upper bound.
_EFFORT_CEILING = 6
# Tools that constitute genuine SIEM EVIDENCE retrieval (as opposed to orientation:
# get_case, list_tasks, get_board, search_patterns, ls/cat, etc.). The depth guard
# counts these, so a task padded with orientation calls is not mistaken for deep work.
_EVIDENCE_TOOLS = frozenset({
    "search", "search_keyword", "profile_field", "get_event_volume",
    "correlate_entity", "correlate_techniques", "get_event",
})
# Hard convergence cap: maximum follow-up tasks the pivot node may auto-create
# per investigation run. Once reached, the pivot processes board updates and
# escalation but creates no new tasks; the queue drains to empty and the run
# terminates cleanly. Prevents unbounded investigation loops.
_MAX_PIVOT_TASKS = 12
_VERDICT_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_MIN_COVERAGE_GAP = timedelta(minutes=10)
# How far past a burst's cessation to still treat as "should have been queried" — the
# low-volume follow-on tail, in bin widths. A payload/success (e.g. a webshell) often
# sits just past a loud burst but BELOW the volume threshold, so the histogram marks it
# quiet; extending the reference span this far surfaces it as an unqueried tail.
_POST_CESSATION_TAIL_BINS = 2
_VERDICT_CONTRACT_TIMEOUT_SECS = 90
_REASSESS_TIMEOUT_SECS = 60
