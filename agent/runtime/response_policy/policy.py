from __future__ import annotations

"""The response policy matrix: which actions each (verdict, subject) cell may offer.

This is the *menu*, fixed in code. `ResponsePolicy` rows store only the operator's
choice from that menu; `execution.py` carries it out.

The subject split is an affordance split, not a taxonomy: a case can be resolved,
and an alert cannot — the only thing that can happen to an alert is that a case gets
created from it. SOAR and SIEM alerts share one subject because that is equally true
of both, so splitting them only ever produced two columns configured identically.

Three deliberate holes:
  - FP on an alert offers only `none`. Dismissing and suppressing alerts were
    considered and cut, so an FP verdict on an alert is a documented no-op rather
    than a missing row.
  - TP on a case may be resolved, but a TP on an *alert* may not: a confirmed
    detection is not finished, it is promoted.
  - There is no `escalate`. It could only raise TheHive severity and leave a note —
    it could not page, notify, or assign anyone — so it promised urgency it did not
    deliver. Documenting the report is the honest version of the same act.

`promote_case` carries the report with it, so there is no separate "document on
alert" action: an alert has no durable page of its own to write to, so the action
promotes it via TheHive and posts the report onto the case that results.
"""

from ...models import ResponsePolicy as _RP
from ..analysis.verdict import VERDICT_ORDER

NONE = _RP.ACTION_NONE
DOCUMENT = _RP.ACTION_DOCUMENT
RESOLVE = _RP.ACTION_RESOLVE
INVESTIGATE = _RP.ACTION_INVESTIGATE
PROMOTE_CASE = _RP.ACTION_PROMOTE_CASE

CASE = _RP.SUBJECT_CASE
ALERT = _RP.SUBJECT_ALERT

SUBJECT_ORDER = (CASE, ALERT)

# A pseudo-verdict row: what to do when an automatic run FAILS, so there is no
# verdict to look up. Stored in the same table (ResponsePolicy.verdict is a plain
# CharField, not tied to the verdict vocabulary) and edited in the same grid.
#
# Scope is deliberately narrow. This covers only runs that produced nothing usable —
# a crash, or a completed run whose verdict could not be parsed. A run that finished
# WITH a verdict always goes through the verdict rows; the verdict pipeline has
# already floored the weak ones before they reach here.
FAILURE_FALLBACK = "failure_fallback"

# Grid rows in display order: the four verdicts, then the failure row.
POLICY_ROWS = VERDICT_ORDER + (FAILURE_FALLBACK,)

# Subjects that existed before SOAR and SIEM alerts were merged into one. Saved rows
# under these keys still resolve, so an operator's configuration survives the merge.
LEGACY_SUBJECTS = {"soar_alert": ALERT, "siem_alert": ALERT}

# (verdict, subject) -> offerable actions, most-active first so the select reads
# as a severity ramp and `none` is always last.
ALLOWED_ACTIONS: dict[tuple[str, str], tuple[str, ...]] = {
    ("tp", CASE): (RESOLVE, DOCUMENT, NONE),
    ("tp", ALERT): (PROMOTE_CASE, NONE),
    ("fp", CASE): (RESOLVE, DOCUMENT, NONE),
    ("fp", ALERT): (NONE,),
    ("inconclusive", CASE): (INVESTIGATE, DOCUMENT, NONE),
    ("inconclusive", ALERT): (PROMOTE_CASE, INVESTIGATE, NONE),
    ("needs_investigation", CASE): (INVESTIGATE, DOCUMENT, NONE),
    ("needs_investigation", ALERT): (INVESTIGATE, PROMOTE_CASE, NONE),
    # No state-changing action is offerable here: a run that produced nothing has
    # earned nothing, so resolving or promoting off the back of it would assert a
    # conclusion that was never reached.
    (FAILURE_FALLBACK, CASE): (INVESTIGATE, DOCUMENT, NONE),
    (FAILURE_FALLBACK, ALERT): (INVESTIGATE, NONE),
}

# Shipped defaults, stated per cell rather than derived. The shape is intentional and
# not a formula: cases are documented but never auto-resolved, an alert worth acting on
# becomes a case, and anything unresolved is handed to the investigation agent.
# "Revert to defaults" in the settings UI restores exactly this table.
DEFAULT_ACTIONS: dict[tuple[str, str], str] = {
    ("tp", CASE): DOCUMENT,
    ("tp", ALERT): PROMOTE_CASE,
    ("fp", CASE): DOCUMENT,
    ("fp", ALERT): NONE,
    ("inconclusive", CASE): DOCUMENT,
    ("inconclusive", ALERT): PROMOTE_CASE,
    ("needs_investigation", CASE): INVESTIGATE,
    ("needs_investigation", ALERT): INVESTIGATE,
    (FAILURE_FALLBACK, CASE): DOCUMENT,
    (FAILURE_FALLBACK, ALERT): NONE,
}


def cells() -> list[tuple[str, str]]:
    """Every (row, subject) pair in display order — verdict rows plus the failure row."""
    return [(r, s) for r in POLICY_ROWS for s in SUBJECT_ORDER]


def row_label(row: str) -> str:
    """Display label for a grid row, whether it is a verdict or the failure row."""
    from ..analysis.verdict import VERDICT_LABELS

    if row == FAILURE_FALLBACK:
        return "Failure fallback"
    return VERDICT_LABELS.get(row, row)


def allowed_actions(verdict: str, subject: str) -> tuple[str, ...]:
    return ALLOWED_ACTIONS.get((verdict, subject), (NONE,))


def default_action(verdict: str, subject: str) -> str:
    return DEFAULT_ACTIONS.get((verdict, subject), NONE)


def is_allowed(verdict: str, subject: str, action: str) -> bool:
    return action in allowed_actions(verdict, subject)


def subject_for_run(run) -> str:
    """Classify a run's subject from its trigger metadata.

    `source_entity_type` already carries the only distinction the matrix makes.
    Which system raised the alert does not change what can be done with it, so the
    trigger provider is deliberately not consulted here.
    """
    meta = getattr(run, "metadata", None) or {}
    return (
        CASE if str(meta.get("source_entity_type") or "").lower() == "case" else ALERT
    )
