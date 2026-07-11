"""Shared module-level constants for the interpret package (regexes, caps, label maps)."""
from __future__ import annotations

import re


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_SECTION_LABELS = {
    "what_showed": (
        "what the last batch showed",
        "what showed",
    ),
    "advanced_objective": (
        "did it advance the task",
        "did it advance",
    ),
    "blocker": (
        "what remains unproven or blocked",
        "what remains blocked",
        "blocked",
    ),
    "next_step_instruction": (
        "suggested next direction",
        "best next step",
        "next step",
    ),
    "stop_state": (
        "stop state",
    ),
    "stop_condition": (
        "success criteria",
        "stop condition",
    ),
    "hypothesis": (
        "working hypothesis",
        "hypothesis",
    ),
}
_STOP_STATE_RE = re.compile(r"\b(continue|complete|negative)\b", re.IGNORECASE)
_ALLOWED_ACTIONS = frozenset({
    "refine_query", "pivot_entity", "retrieve_specific_event",
    "profile_window", "stop_negative", "stop_completed",
})
_TERMINAL_ACTIONS = frozenset({"stop_completed", "stop_negative"})
_CONTINUE_ACTIONS = frozenset({"pivot_entity", "retrieve_specific_event", "profile_window", "refine_query"})
_FORCE_CONTINUE_SIGNALS = frozenset({
    "TRUNCATED", "SATURATED", "FLOODED", "ORIENTATION_ONLY", "INVALID_TIME_WINDOW", "TOOL_ERROR",
})
# After this many consecutive non-advancing cycles (NO_NEW_EVIDENCE / EMPTY on the same
# objective), the CURRENT DIRECTION is exhausted: interpret was echoing the same suggestion
# back to itself (ledger dump -> model -> same suggestion). Force a change of approach and
# drop the stuck forward target so the fixed point breaks.
_STUCK_RETRIES = 2
# General per-task convergence brake. STUCK (above) catches a REPEATED identical direction;
# this catches WANDERING — the agent varying its action type (pivot->retrieve->profile) for
# many cycles while never crystallizing a new confirmed finding. It measures convergence
# DIRECTLY (cycles since confirmed_findings last grew) rather than pattern-matching a query
# shape, and is keyed on finding growth (NOT mere advanced_objective) so the advancement
# flicker that resets STUCK cannot mask it. Session review of 291 interpret cycles showed the
# old window/focus stagnation heuristics fired 0 times while tasks thrashed 29-52 cycles
# unbraked; this is their general replacement. Set well above the median task length (~4
# cycles) so it only engages on genuine runaway. It NUDGES the model to converge; the
# per-task tool-call cap remains the hard backstop.
_NO_PROGRESS_BRAKE_CYCLES = 8
_CONFIRMED_FINDINGS_KEEP = 12
# On the ready-to-assess handoff, how many recent tool-call/tool-result messages to carry
# forward so `assess` can verify a SIEM query ran and synthesize the report from real
# evidence, without dragging the entire result history into the wrap-up context.
_READY_EVIDENCE_KEEP = 12
_DEFAULT_STOP_CONDITION = (
    "Retrieve concrete task-specific evidence or a well-scoped confirmed-negative query."
)
_REPORT_INSTRUCTION = (
    "Write the task report from the assimilated ledger evidence. Do not call more "
    "tools unless the ledger is materially wrong."
)
_PIVOT_KEYS = (
    "field", "value", "source_level", "role", "confidence",
    "status", "failure_count", "last_failure_reason", "broader_alternative",
)
_PIVOT_FAILURE_SIGNALS = (
    ("INVALID_TIME_WINDOW", "invalid_time_window"),
    ("TOOL_ERROR", "tool_error"),
    ("FLOODED", "flooded"),
    ("TRUNCATED", "truncated"),
    ("WRONG_REPRESENTATION", "wrong_representation"),
    ("NO_NEW_EVIDENCE", "no_new_evidence"),
    ("EMPTY", "empty"),
)
# How many (discriminator, window) trials to remember per task. query_trials is the
# OUTCOME-annotated history the interpreter READS to reason over its own failures —
# it distinguishes "repeated an EMPTY query" (matching logic is wrong: profile the real
# values / subtract the alert's own value) from "repeated a FLOOD" (narrow) from "reused a
# window" (move). That semantic distinction is what the signals alone cannot carry.
_QUERY_TRIALS_KEEP = 20
# The forward-stage channel. Kept SEPARATE from next_step_instruction because it is
# a persistent semantic target ("what happened next on the same asset") that must
# survive cycles where the immediate step is a local refinement — folding it into the
# single instruction let a flooded scan window keep re-narrowing in place instead of
# stepping one kill-chain stage forward (diagnosed: run b914fe36 orbited the 12:17 scan
# window for its whole life; run 75cc7dcf, which carried this field, forward-traced into
# the post-scan execution/privesc window).
_ADJACENCY_KEYS = ("entity", "time_direction", "window_hint", "representation_hint")
