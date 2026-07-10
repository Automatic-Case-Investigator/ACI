"""confident_false_negative — the SOC-critical error: the report confidently DENIES a
ground-truth attack phase that actually occurred (e.g. "[Confirmed] No Impact",
"exfiltration is unproven", "no confirmed execution").

A phase the report simply misses, or flags as open/unknown, is tolerable — a wrong
*certainty of absence* actively misleads the analyst, and it is the exact Fox failure
mode. This is a deterministic, high-precision proxy: it fires only when a strong
absence-assertion co-occurs (same sentence) with a tactic keyword for a phase that IS in
ground truth. A judge-based metric can later refine the attribution; this catches the
blatant cases cheaply. Recon/scan phases are excluded — denying reconnaissance is not a
compromise miss.
"""
from __future__ import annotations

import re

from ..base import Metric, MetricResult
from ..context import ScoringContext
from ..registry import register

# Post-compromise phases where a confident denial is analyst-harming, → the tactic
# keywords the report would use. Keyed by AIT phase name, so it is reusable across
# scenarios (they share this phase vocabulary).
# Keep each tactic's keywords phase-SPECIFIC. Bare generic tokens ("execution",
# "escalation") are deliberately excluded: they collide with unrelated sentences the
# report writes about other phases — e.g. "remote payload execution point remains
# unconfirmed" (a C2/reverse-shell denial) or "did not surface execution telemetry"
# (generic) would otherwise be misattributed as a confident *webshell* denial. This
# metric is a high-precision proxy, and a phase the report merely omits is tolerated,
# so an over-broad keyword that fires on omissions of *other* phases is a false positive.
_PHASE_TACTIC_KEYWORDS = {
    "webshell": ("webshell", "web shell", "web-shell", "code execution"),
    "cracking": ("credential", "password crack", "hash dump", "cracking", "wp_users"),
    "reverse_shell": ("reverse shell", "reverse-shell", "command and control", "c2",
                      "callback", "beacon"),
    "privilege_escalation": ("privilege escalation", "privesc"),
    "service_stop": ("service stop", "impact", "destructive", "ransom"),
    "dnsteal": ("exfiltration", "exfil", "data theft", "dnsteal", "data leaving"),
}

# Strong "confident absence" language. Bare "no"/"not" are deliberately excluded — too
# noisy; these are the phrasings analysts read as a definitive negative.
_NEGATION_RE = re.compile(
    r"(no evidence|no confirmed|no sign|no indication|not confirmed|not observed|"
    r"not established|not proven|unproven|unconfirmed|ruled out|did not|absence of|"
    r"could not (?:find|confirm|establish)|failed to (?:find|confirm))",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"[.\n;]")


@register
class ConfidentFalseNegative(Metric):
    name = "confident_false_negative"
    needs_judge = False

    def score(self, ctx: ScoringContext) -> MetricResult:
        sentences = [s.strip() for s in _SENTENCE_SPLIT.split(ctx.report.text or "")]
        flagged: dict[str, bool] = {}
        offending: dict[str, str] = {}
        for phase in ctx.scenario.phases:
            keywords = _PHASE_TACTIC_KEYWORDS.get(phase.name)
            if not keywords:
                continue  # recon/scan phases not FN-relevant
            hit = False
            for sentence in sentences:
                low = sentence.lower()
                if _NEGATION_RE.search(low) and any(k in low for k in keywords):
                    hit, offending[phase.name] = True, sentence[:200]
                    break
            flagged[phase.name] = hit
        return MetricResult(
            name=self.name,
            kind="per_key",  # → per-phase false-negative rate over trials
            value=flagged,
            detail={
                "count": sum(1 for v in flagged.values() if v),
                "offending": offending,
                "entry_point": ctx.entry_point,
            },
        )
