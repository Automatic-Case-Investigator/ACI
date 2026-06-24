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
    apply_open_gaps_policy,
)


TP_BLOCK = """\
## Verdict
Compromise confirmed; high severity; contained.

```json
{
  "verdict": "tp",
  "confidence": "high",
  "matched_patterns": [],
  "supporting_evidence": ["event 1712 — reverse shell in crontab"],
  "contradicting_evidence": [],
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
        v = {"verdict": "tp", "confidence": "high", "supporting_evidence": []}
        problems = validate_verdict(v)
        self.assertTrue(any("supporting_evidence" in p for p in problems))


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


class TestImpactScopeFields(unittest.TestCase):

    def test_impact_scope_round_trip(self):
        text = (
            '```json\n{"verdict": "tp", "confidence": "high", '
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
             "supporting_evidence": ["e1"], "impact_state": "contained", "scope_state": "isolated"}
        self.assertEqual(validate_verdict(v), [])


class TestOpenGapsPolicy(unittest.TestCase):

    def _tp_with_gaps(self, gaps):
        return {"verdict": "tp", "confidence": "high",
                "supporting_evidence": ["e1"], "missing_evidence": gaps}

    def test_strict_demotes_on_any_gap(self):
        v = self._tp_with_gaps(["one minor gap"])
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_non_strict_no_demotion_for_small_non_blocking_gaps(self):
        v = self._tp_with_gaps(["additional log source would help", "confirm persistence mechanism"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertFalse(demoted)
        self.assertEqual(out["verdict"], "tp")

    def test_non_strict_demotes_on_three_or_more_gaps(self):
        v = self._tp_with_gaps(["gap a", "gap b", "gap c"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_non_strict_demotes_on_blocking_keyword(self):
        v = self._tp_with_gaps(["cannot rule out lateral movement"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)
        self.assertEqual(out["verdict"], "needs_investigation")

    def test_non_strict_demotes_no_telemetry_keyword(self):
        v = self._tp_with_gaps(["no telemetry available for C2 traffic"])
        out, demoted = apply_open_gaps_policy(v, strict=False)
        self.assertTrue(demoted)

    def test_no_missing_evidence_never_demotes(self):
        v = {"verdict": "tp", "confidence": "high",
             "supporting_evidence": ["e1"], "missing_evidence": []}
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertFalse(demoted)

    def test_inconclusive_never_demoted(self):
        v = {"verdict": "inconclusive", "confidence": "low", "missing_evidence": ["gap"]}
        out, demoted = apply_open_gaps_policy(v, strict=True)
        self.assertFalse(demoted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
