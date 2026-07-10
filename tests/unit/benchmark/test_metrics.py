"""Offline unit tests for the verdict / confident-FN / cost metrics.

Pure functions of a ScoringContext — no Django, no live services.
"""
from __future__ import annotations

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, _ROOT)

from benchmark import scoring  # noqa: E402
from benchmark.scoring import ScenarioSpec, ScoringContext  # noqa: E402

_SPEC = ScenarioSpec.from_dict({
    "name": "toy",
    "expected_verdict": {"verdict": "tp", "severity": "critical", "scope": ["wazuh-client"]},
    "phases": [
        {"name": "webshell", "start": "2022-01-18T12:38:00Z", "end": "2022-01-18T12:38:30Z"},
        {"name": "dnsteal", "start": "2022-01-18T13:00:00Z", "end": "2022-01-18T13:10:00Z"},
        {"name": "network_scans", "start": "2022-01-18T11:59:00Z", "end": "2022-01-18T12:17:00Z"},
    ],
})


def _score(metric, *, report="", verdict=None, meta=None):
    ctx = ScoringContext.build(_SPEC, report, verdict=verdict, meta=meta)
    (result,) = scoring.run_all(ctx, [metric])
    return result


class VerdictCorrectnessTest(unittest.TestCase):
    def test_exact_match(self):
        r = _score("verdict_correctness", verdict={"verdict": "tp"})
        self.assertTrue(r.value)
        self.assertFalse(r.detail["under_called"])

    def test_under_call_flagged(self):
        r = _score("verdict_correctness", verdict={"verdict": "needs_investigation"})
        self.assertFalse(r.value)                 # not a match
        self.assertTrue(r.detail["under_called"])  # expected tp, called weaker

    def test_wrong_disposition(self):
        r = _score("verdict_correctness", verdict={"verdict": "fp"})
        self.assertFalse(r.value)


class ConfidentFalseNegativeTest(unittest.TestCase):
    def test_flags_denied_ground_truth_tactic(self):
        # webshell + dnsteal are ground truth; the report confidently denies exfiltration.
        report = "The webshell was confirmed. No evidence of exfiltration was found."
        r = _score("confident_false_negative", report=report)
        self.assertTrue(r.value["dnsteal"])      # denied a phase that occurred
        self.assertFalse(r.value["webshell"])    # confirmed, not denied
        self.assertEqual(r.detail["count"], 1)

    def test_does_not_flag_absence_of_a_non_ground_truth_tactic(self):
        # "no lateral movement" is CORRECT (not a Fox phase) — must not be flagged.
        report = "No evidence of lateral movement. The webshell executed successfully."
        r = _score("confident_false_negative", report=report)
        self.assertEqual(r.detail["count"], 0)

    def test_recon_denial_is_not_counted(self):
        report = "No evidence of network scans was observed."
        r = _score("confident_false_negative", report=report)
        self.assertNotIn("network_scans", r.value)  # recon phases are excluded

    def test_generic_execution_denial_is_not_misattributed_to_webshell(self):
        # Regression (fox run 34bfb7a1): sentences about C2 "payload execution" or
        # generic "execution telemetry" must NOT be flagged as a confident *webshell*
        # denial — the report merely omitted webshell, which the metric tolerates.
        for report in (
            "The network callback or remote payload execution point remains unconfirmed "
            "because the retrieved event does not contain destination-network fields.",
            "The reviewed Wazuh slices did not surface execution telemetry: no audit, "
            "syscheck, sudo, or PAM command evidence appeared.",
        ):
            r = _score("confident_false_negative", report=report)
            self.assertFalse(r.value["webshell"], report)

    def test_webshell_specific_denial_is_still_flagged(self):
        # A genuine confident denial of the webshell phase must still fire.
        r = _score("confident_false_negative",
                   report="No evidence of a webshell was found on the host.")
        self.assertTrue(r.value["webshell"])


class CostToVerdictTest(unittest.TestCase):
    def test_reads_tokens_from_meta(self):
        r = _score("cost_to_verdict", meta={"status": "completed",
                                            "tokens": {"input": 5_000_000, "output": 50_000,
                                                       "model_calls": 120}})
        self.assertEqual(r.value["input_tokens"], 5_000_000)
        self.assertEqual(r.value["output_tokens"], 50_000)
        self.assertEqual(r.value["model_calls"], 120)

    def test_missing_tokens_is_zero(self):
        r = _score("cost_to_verdict", meta={})
        self.assertEqual(r.value, {"input_tokens": 0, "output_tokens": 0, "model_calls": 0})


if __name__ == "__main__":
    unittest.main(verbosity=2)
