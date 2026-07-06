"""
Offline test: diagnosis verdict parsing, validation, and citation policy.

Pure-Python (no Django / LLM / MCP). Run from project root with:
    python .claude/skills/run-aci-backend/tests/test_verdict_parsing.py -v
"""
from __future__ import annotations

import os
import sys
import unittest

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)

from agent.runtime.analysis.verdict import (
    parse_verdict,
    validate_verdict,
    citation_check,
    apply_citation_policy,
    apply_completeness_floor,
    apply_open_gaps_policy,
    normalize_followup_gaps,
    is_offensive_alert,
    classify_fp_gaps,
    apply_success_verification_floor,
    apply_verdict_integrity,
)


TP_BLOCK = """\
## Verdict
Compromise confirmed; high severity; contained.

```json
{
  "verdict": "tp",
  "confidence": "high",
  "classification_basis": "malicious_evidence",
  "matched_patterns": [],
  "supporting_evidence": ["event 1712 — reverse shell in crontab"],
  "contradicting_evidence": [],
  "blocking_gaps": [],
  "nonblocking_gaps": [],
  "missing_evidence": [],
  "recommended_action": "escalate"
}
```
"""


class TestParseVerdict(unittest.TestCase):

    def test_parses_fenced_json_block(self):
        v = parse_verdict(TP_BLOCK)
        self.assertIsNotNone(v)
        self.assertEqual(v["verdict"], "tp")
        self.assertEqual(v["confidence"], "high")
        self.assertEqual(v["supporting_evidence"], ["event 1712 — reverse shell in crontab"])

    def test_parses_bare_fence_without_json_tag(self):
        text = '```\n{"verdict": "fp", "confidence": "high", "supporting_evidence": ["pattern x"]}\n```'
        v = parse_verdict(text)
        self.assertIsNotNone(v)
        self.assertEqual(v["verdict"], "fp")

    def test_last_block_wins(self):
        text = (
            '```json\n{"verdict": "inconclusive", "confidence": "low"}\n```\n'
            '```json\n{"verdict": "tp", "confidence": "high", "supporting_evidence": ["e1"]}\n```'
        )
        v = parse_verdict(text)
        self.assertEqual(v["verdict"], "tp")

    def test_returns_none_when_no_block(self):
        self.assertIsNone(parse_verdict("Just a prose report with no verdict block."))

    def test_returns_none_on_malformed_json(self):
        self.assertIsNone(parse_verdict('```json\n{"verdict": "tp", oops}\n```'))

    def test_ignores_fenced_json_without_verdict_key(self):
        text = '```json\n{"foo": "bar"}\n```'
        self.assertIsNone(parse_verdict(text))

    def test_parses_trailing_bare_json_object(self):
        text = (
            "## Findings\nRoutine command audit event.\n\n"
            '{"verdict":"benign","confidence":"medium","supporting_evidence":["alert:~1"],'
            '"matched_patterns":[],"new_leads":[]}'
        )
        v = parse_verdict(text)
        self.assertIsNotNone(v)
        self.assertEqual(v["verdict"], "fp")
        self.assertEqual(v["confidence"], "medium")

    def test_normalizes_case_and_string_lists(self):
        text = '```json\n{"verdict": "TP", "confidence": "High", "supporting_evidence": "single string"}\n```'
        v = parse_verdict(text)
        self.assertEqual(v["verdict"], "tp")
        self.assertEqual(v["confidence"], "high")
        self.assertEqual(v["supporting_evidence"], ["single string"])

    def test_missing_list_fields_default_empty(self):
        text = '```json\n{"verdict": "needs_investigation", "confidence": "low"}\n```'
        v = parse_verdict(text)
        self.assertEqual(v["matched_patterns"], [])
        self.assertEqual(v["contradicting_evidence"], [])
        self.assertEqual(v["blocking_gaps"], [])
        self.assertEqual(v["nonblocking_gaps"], [])

    def test_legacy_missing_evidence_copied_to_nonblocking_gaps(self):
        text = (
            '```json\n{"verdict": "needs_investigation", "confidence": "low", '
            '"missing_evidence": ["collect EDR process tree"]}\n```'
        )
        v = parse_verdict(text)
        self.assertEqual(v["missing_evidence"], ["collect EDR process tree"])
        self.assertEqual(v["blocking_gaps"], [])
        self.assertEqual(v["nonblocking_gaps"], ["collect EDR process tree"])

    def test_legacy_blocking_missing_evidence_copied_to_blocking_gaps(self):
        text = (
            '```json\n{"verdict": "needs_investigation", "confidence": "low", '
            '"missing_evidence": ["no telemetry available for C2 traffic"]}\n```'
        )
        v = parse_verdict(text)
        self.assertEqual(v["blocking_gaps"], ["no telemetry available for C2 traffic"])
        self.assertEqual(v["nonblocking_gaps"], [])


class TestValidateVerdict(unittest.TestCase):

    def test_valid_verdict_has_no_problems(self):
        v = parse_verdict(TP_BLOCK)
        self.assertEqual(validate_verdict(v), [])

    def test_bad_verdict_value_flagged(self):
        v = {"verdict": "maybe", "confidence": "high", "supporting_evidence": ["e"]}
        problems = validate_verdict(v)
        self.assertTrue(any("verdict must be one of" in p for p in problems))

    def test_bad_confidence_flagged(self):
        v = {"verdict": "inconclusive", "confidence": "certain"}
        problems = validate_verdict(v)
        self.assertTrue(any("confidence must be one of" in p for p in problems))

    def test_tp_without_evidence_flagged(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence", "supporting_evidence": []}
        problems = validate_verdict(v)
        self.assertTrue(any("supporting_evidence" in p for p in problems))

    def test_tp_without_malicious_basis_flagged(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "insufficient_evidence", "supporting_evidence": ["e1"]}
        problems = validate_verdict(v)
        self.assertTrue(any("malicious_evidence" in p for p in problems))

    def test_fp_without_benign_basis_flagged(self):
        v = {"verdict": "fp", "confidence": "high",
             "classification_basis": "insufficient_evidence", "supporting_evidence": ["e1"]}
        problems = validate_verdict(v)
        self.assertTrue(any("benign_evidence" in p for p in problems))


class TestCitationPolicy(unittest.TestCase):

    def test_tp_with_evidence_passes(self):
        v = parse_verdict(TP_BLOCK)
        self.assertTrue(citation_check(v))
        out, demoted = apply_citation_policy(v)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")

    def test_uncited_tp_demoted_to_inconclusive(self):
        v = {"verdict": "tp", "confidence": "high", "supporting_evidence": [],
             "recommended_action": "escalate"}
        self.assertFalse(citation_check(v))
        out, demoted = apply_citation_policy(v)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "inconclusive")
        self.assertEqual(out["demoted_from"], "tp")
        self.assertIn("demoted", out["recommended_action"].lower())

    def test_uncited_fp_demoted(self):
        v = {"verdict": "fp", "confidence": "high", "supporting_evidence": []}
        out, demoted = apply_citation_policy(v)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "inconclusive")

    def test_inconclusive_never_demoted(self):
        v = {"verdict": "inconclusive", "confidence": "low", "supporting_evidence": []}
        self.assertTrue(citation_check(v))
        out, demoted = apply_citation_policy(v)
        self.assertFalse(demoted)

    def test_needs_investigation_passes_without_evidence(self):
        v = {"verdict": "needs_investigation", "confidence": "low", "supporting_evidence": []}
        self.assertTrue(citation_check(v))


class TestCompletenessFloor(unittest.TestCase):
    """The completeness floor (Phase 0 #9): an escalated or budget-truncated run
    must not clear a case as benign."""

    def _fp(self):
        return {"verdict": "fp", "confidence": "high",
                "classification_basis": "benign_evidence",
                "supporting_evidence": ["benign event 5"]}

    def test_escalated_fp_floored_to_needs_investigation(self):
        out, floored = apply_completeness_floor(self._fp(), escalation_posted=True)
        self.assertTrue(floored)
        self.assertEqual(out["verdict"], "needs_investigation")
        self.assertEqual(out["demoted_from"], "fp")
        self.assertIn("escalation", out["reassessment_reason"].lower())

    def test_over_budget_fp_floored(self):
        out, floored = apply_completeness_floor(self._fp(), over_budget=True)
        self.assertTrue(floored)
        self.assertEqual(out["verdict"], "needs_investigation")
        self.assertIn("budget", out["reassessment_reason"].lower())

    def test_clean_complete_fp_not_floored(self):
        out, floored = apply_completeness_floor(
            self._fp(), escalation_posted=False, over_budget=False)
        self.assertFalse(floored)
        self.assertEqual(out["verdict"], "fp")

    def test_tp_never_floored(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["e1"]}
        out, floored = apply_completeness_floor(
            v, escalation_posted=True, over_budget=True)
        self.assertFalse(floored)
        self.assertEqual(out["verdict"], "tp")

    def test_inconclusive_never_floored(self):
        v = {"verdict": "inconclusive", "confidence": "low"}
        out, floored = apply_completeness_floor(
            v, escalation_posted=True, over_budget=True)
        self.assertFalse(floored)
        self.assertEqual(out["verdict"], "inconclusive")

    def test_idempotent(self):
        once, _ = apply_completeness_floor(self._fp(), escalation_posted=True)
        twice, floored2 = apply_completeness_floor(once, escalation_posted=True)
        self.assertFalse(floored2)
        self.assertEqual(twice["verdict"], "needs_investigation")

    def test_both_reasons_listed(self):
        out, floored = apply_completeness_floor(
            self._fp(), escalation_posted=True, over_budget=True)
        self.assertTrue(floored)
        self.assertIn("escalation", out["reassessment_reason"].lower())
        self.assertIn("budget", out["reassessment_reason"].lower())


class TestImpactScopeFields(unittest.TestCase):

    def test_impact_scope_round_trip(self):
        text = (
            '```json\n{"verdict": "tp", "confidence": "high", '
            '"classification_basis": "malicious_evidence", '
            '"impact_state": "active", "scope_state": "lateral_spread", '
            '"supporting_evidence": ["e1"]}\n```'
        )
        v = parse_verdict(text)
        self.assertEqual(v["impact_state"], "active")
        self.assertEqual(v["scope_state"], "lateral_spread")

    def test_invalid_impact_coerces_to_unknown(self):
        text = '```json\n{"verdict": "inconclusive", "confidence": "low", "impact_state": "ongoing"}\n```'
        v = parse_verdict(text)
        self.assertEqual(v["impact_state"], "unknown")

    def test_missing_fields_default_to_unknown(self):
        v = parse_verdict(TP_BLOCK)
        self.assertEqual(v.get("impact_state"), "unknown")
        self.assertEqual(v.get("scope_state"), "unknown")

    def test_validate_catches_bad_impact_state(self):
        v = {"verdict": "inconclusive", "confidence": "low",
             "supporting_evidence": [], "impact_state": "critical", "scope_state": "unknown"}
        problems = validate_verdict(v)
        self.assertTrue(any("impact_state" in p for p in problems))

    def test_validate_catches_bad_scope_state(self):
        v = {"verdict": "inconclusive", "confidence": "low",
             "supporting_evidence": [], "impact_state": "unknown", "scope_state": "global"}
        problems = validate_verdict(v)
        self.assertTrue(any("scope_state" in p for p in problems))

    def test_validate_passes_valid_enum_values(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["e1"], "impact_state": "contained", "scope_state": "isolated"}
        self.assertEqual(validate_verdict(v), [])


class TestOpenGapsPolicy(unittest.TestCase):

    def _tp_with_gaps(self, gaps):
        return {"verdict": "tp", "confidence": "high",
                "classification_basis": "malicious_evidence",
                "supporting_evidence": ["e1"], "missing_evidence": gaps}

    def test_nonblocking_gaps_do_not_demote(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["event 1712"],
             "nonblocking_gaps": ["additional log source would help"]}
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")

    def test_blocking_gaps_demote(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["event 1712"],
             "blocking_gaps": ["cannot distinguish admin from attacker"]}
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_tp_with_missing_basis_demotes(self):
        v = self._tp_with_gaps(["one minor gap"])
        v.pop("classification_basis")
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_legacy_generic_missing_evidence_does_not_demote_by_count(self):
        v = self._tp_with_gaps(["gap a", "gap b", "gap c"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")

    def test_legacy_missing_evidence_with_blocking_phrase_demotes(self):
        v = self._tp_with_gaps(["cannot rule out lateral movement"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_fp_without_benign_basis_demotes(self):
        v = {"verdict": "fp", "confidence": "high",
             "supporting_evidence": ["no malicious evidence found"],
             "nonblocking_gaps": ["collect EDR process tree"]}
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_fp_with_benign_basis_and_nonblocking_gaps_remains_fp(self):
        v = {"verdict": "fp", "confidence": "high",
             "classification_basis": "benign_evidence",
             "supporting_evidence": ["change ticket approved crontab edit"],
             "nonblocking_gaps": ["no EDR process tree available"]}
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "fp")

    def test_session_regression_tp_with_followup_gaps_remains_tp(self):
        v = self._tp_with_gaps(["additional log source would help", "confirm persistence mechanism"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")

    def test_session_regression_initial_access_gap_is_nonblocking_for_proven_tp(self):
        v = {
            "verdict": "tp",
            "confidence": "high",
            "classification_basis": "malicious_evidence",
            "supporting_evidence": [
                "Syscheck modified /var/spool/cron/crontabs/user with reverse-shell cron entry"
            ],
            "blocking_gaps": ["Initial access source IP not retrieved from telemetry"],
            "nonblocking_gaps": ["No direct network telemetry confirming callback"],
        }
        normalized = normalize_followup_gaps(v)
        out, demoted = apply_open_gaps_policy(normalized, strict=False)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")
        self.assertEqual(out["blocking_gaps"], [])
        self.assertIn("Initial access source IP not retrieved from telemetry", out["nonblocking_gaps"])

    def test_no_missing_evidence_never_demotes(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["e1"], "missing_evidence": []}
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertFalse(demoted)

    def test_inconclusive_never_demoted(self):
        v = {"verdict": "inconclusive", "confidence": "low", "missing_evidence": ["gap"]}
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertFalse(demoted)


class OffensiveAlertDetectionTests(unittest.TestCase):
    def test_detects_scan_recon_from_matched_patterns(self):
        v = {"verdict": "fp", "matched_patterns": ["T1595.002 vulnerability scanning"],
             "supporting_evidence": []}
        self.assertTrue(is_offensive_alert(v))

    def test_detects_wpscan_from_supporting_evidence(self):
        v = {"verdict": "fp", "matched_patterns": [],
             "supporting_evidence": ["user-agent WPScan v3.8.20 probing plugin paths"]}
        self.assertTrue(is_offensive_alert(v))

    def test_non_offensive_alert_not_flagged(self):
        v = {"verdict": "fp", "matched_patterns": [],
             "supporting_evidence": ["change ticket approved crontab edit"]}
        self.assertFalse(is_offensive_alert(v))


class ClassifyFpGapsTests(unittest.TestCase):
    def test_fp_success_gap_promoted_to_blocking(self):
        v = {"verdict": "fp", "confidence": "high",
             "nonblocking_gaps": ["No post-scan success or follow-on activity was confirmed",
                                  "Broad query was truncated at 10,000 hits"]}
        out, changed = classify_fp_gaps(v)
        self.assertTrue(changed)
        self.assertIn("No post-scan success or follow-on activity was confirmed", out["blocking_gaps"])
        # Unrelated gap stays nonblocking.
        self.assertIn("Broad query was truncated at 10,000 hits", out["nonblocking_gaps"])
        self.assertNotIn("No post-scan success or follow-on activity was confirmed", out["nonblocking_gaps"])

    def test_fp_benign_followup_gap_not_promoted(self):
        v = {"verdict": "fp", "confidence": "high",
             "nonblocking_gaps": ["no EDR process tree available"]}
        out, changed = classify_fp_gaps(v)
        self.assertFalse(changed)
        self.assertEqual(out["nonblocking_gaps"], ["no EDR process tree available"])

    def test_tp_gaps_untouched(self):
        v = {"verdict": "tp", "nonblocking_gaps": ["lateral movement not fully scoped"]}
        out, changed = classify_fp_gaps(v)
        self.assertFalse(changed)


class SuccessVerificationFloorTests(unittest.TestCase):
    def test_fp_offensive_without_success_check_floored(self):
        v = {"verdict": "fp", "confidence": "high",
             "classification_basis": "benign_evidence",
             "matched_patterns": ["T1595.002 vulnerability scanning"],
             "supporting_evidence": ["HTTP HEAD requests to plugin paths returning 404"]}
        out, floored = apply_success_verification_floor(v, offensive_alert=True)
        self.assertTrue(floored)
        self.assertEqual(out["verdict"], "needs_investigation")
        self.assertEqual(out["demoted_from"], "fp")

    def test_fp_offensive_with_benign_justification_not_floored(self):
        v = {"verdict": "fp", "confidence": "high",
             "matched_patterns": ["vulnerability scanning"],
             "supporting_evidence": ["approved internal vulnerability management scan window"]}
        out, floored = apply_success_verification_floor(v, offensive_alert=True)
        self.assertFalse(floored)

    def test_fp_offensive_with_success_negative_not_floored(self):
        # A confirmed success-negative means the run DID check downstream success.
        v = {"verdict": "fp", "confidence": "high",
             "matched_patterns": ["scan"],
             "supporting_evidence": ["no successful login or authenticated session followed the scan"]}
        out, floored = apply_success_verification_floor(v, offensive_alert=True)
        self.assertFalse(floored)

    def test_non_offensive_fp_not_floored(self):
        v = {"verdict": "fp", "supporting_evidence": ["approved crontab edit"]}
        out, floored = apply_success_verification_floor(v, offensive_alert=False)
        self.assertFalse(floored)


class VerdictIntegrityPipelineTests(unittest.TestCase):
    def _session_fp(self):
        # Reproduces the triage verdict from session 49ae3801 that wrongly auto-closed.
        return {
            "verdict": "fp", "confidence": "high",
            "classification_basis": "benign_evidence",
            "matched_patterns": ["T1595.002 vulnerability scanning", "Web reconnaissance",
                                 "WPScan user-agent"],
            "supporting_evidence": [
                "Retrieved raw events show repeated HTTP HEAD requests returning 404",
                "Alert family rule.id=31151 describes multiple web server 400 error codes",
            ],
            "blocking_gaps": [],
            "nonblocking_gaps": [
                "Broad query was truncated at 10,000 hits",
                "No post-scan success or follow-on activity was confirmed in the retrieved sample",
                "Source IP historical context was not fully resolved",
            ],
        }

    def test_session_regression_offensive_fp_floored(self):
        # The core fix: this high-confidence benign close must NOT stand.
        out, notes = apply_verdict_integrity(self._session_fp(), strict=True)
        self.assertEqual(out["verdict"], "needs_investigation")
        self.assertTrue(notes)

    def test_pipeline_idempotent(self):
        out1, _ = apply_verdict_integrity(self._session_fp(), strict=True)
        out2, notes2 = apply_verdict_integrity(out1, strict=True)
        self.assertEqual(out2["verdict"], "needs_investigation")
        self.assertEqual(notes2, [])  # already floored — no further changes

    def test_legitimate_benign_fp_survives(self):
        # A properly-justified benign FP on a non-offensive alert is untouched.
        v = {"verdict": "fp", "confidence": "high",
             "classification_basis": "benign_evidence",
             "supporting_evidence": ["change ticket approved crontab edit"],
             "nonblocking_gaps": ["no EDR process tree available"]}
        out, notes = apply_verdict_integrity(v, strict=False)
        self.assertEqual(out["verdict"], "fp")
        self.assertEqual(notes, [])

    def test_proven_tp_survives_with_followup_relief(self):
        v = {"verdict": "tp", "confidence": "high",
             "classification_basis": "malicious_evidence",
             "supporting_evidence": ["Syscheck modified crontab with reverse-shell entry"],
             "blocking_gaps": ["Initial access source IP not retrieved from telemetry"],
             "nonblocking_gaps": []}
        out, notes = apply_verdict_integrity(v, strict=False)
        self.assertEqual(out["verdict"], "tp")
        self.assertEqual(out["blocking_gaps"], [])

    def test_confirmed_web_scan_is_tp_despite_downstream_gaps(self):
        v = {
            "verdict": "tp",
            "confidence": "high",
            "classification_basis": "malicious_evidence",
            "matched_patterns": ["web_scan", "recon", "wp_scan", "nmap_fingerprint"],
            "supporting_evidence": [
                "_id=JXN22DrN36SXxV2T4XC2 rule.id=31151 "
                "rule.groups=[web,accesslog,web_scan,recon] MITRE T1595.002",
                "_id=cw-ePTQlgl6o4GqnbwvY user-agent=WPScan v3.8.20",
            ],
            "blocking_gaps": [
                "successful authenticated session artifacts not confirmed",
                "process execution telemetry on wazuh-client not confirmed",
                "confirmed C2 callback destination not confirmed",
            ],
            "nonblocking_gaps": [],
        }
        out, notes = apply_verdict_integrity(v, strict=False)
        self.assertEqual(out["verdict"], "tp")
        self.assertEqual(out["blocking_gaps"], [])
        self.assertIn(
            "successful authenticated session artifacts not confirmed",
            out["nonblocking_gaps"],
        )
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
