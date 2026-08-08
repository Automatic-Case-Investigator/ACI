"""Shared module-level constants for the nodes_flow package (regexes, caps, timeouts)."""
from __future__ import annotations

from datetime import timedelta
import re


_VERDICT_REPAIR_TIMEOUT_SECS = 45
# How many times the assess node re-injects a "keep working" / "fix the report" nudge
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
_VERDICT_CONTRACT_TIMEOUT_SECS = 90
_REASSESS_TIMEOUT_SECS = 60

# Re-exported from `graph.coverage`, which owns them now — `nodes_flow` cannot be
# their home because `graph.interpretation` and `nodes_loop` need them too.
from ..coverage import (  # noqa: E402,F401
    _EVIDENCE_TOOLS, _MIN_COVERAGE_GAP, _POST_CESSATION_TAIL_BINS, _SEARCH_RESULT_TOOLS,
)
