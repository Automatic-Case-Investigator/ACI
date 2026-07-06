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
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import AIMessage  # noqa: E402

from agent.runtime.graph.synthesis import _phase_scaffold, _synthesize_analyst_report  # noqa: E402


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


class _CapturingModel:
    """Captures the synthesis prompt so we can assert its structure, returns a stub report."""

    def __init__(self):
        self.prompt = ""

    async def ainvoke(self, messages):
        # messages = [SystemMessage, HumanMessage(prompt)]
        self.prompt = messages[-1].content
        return AIMessage(content="## Verdict\nfalse positive; low; contained\n")


class ReportPromptStructureTest(unittest.TestCase):
    def _prompt(self) -> str:
        model = _CapturingModel()
        state = {"case_id": "~c", "question": "what happened?", "agent_name": "investigation"}
        _run(_synthesize_analyst_report(
            model, state, key_findings=["- a finding"], facts=[], hypotheses=[],
            completed=[], report_guardrails="- floor", phase_scaffold="- Execution: EVIDENCE PRESENT",
        ))
        return model.prompt

    def test_prompt_lists_the_six_bare_altitude_headers(self):
        p = self._prompt()
        for header in ("## Verdict", "## Executive Summary", "## Confirmed Timeline",
                       "## Phase-by-Phase Findings", "## Open Gaps", "## Recommended Actions"):
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
