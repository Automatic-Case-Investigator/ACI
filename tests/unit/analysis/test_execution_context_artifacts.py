"""Execution-context fields are artifacts, not decoration.

An event's fields split into what was done (actor, operand) and the circumstances it
ran in (working directory, terminal, session). The extractor only ever mined the
first group, so a privileged command's `pwd` never reached the board — it could not
be correlated, could not be cited, and could not anchor a lead.

That is not a cosmetic loss. In session 5ec9ab88 the agent retrieved
`sudo … PWD=/var/www/…/wp-content/uploads/2022/01 ; USER=root ; COMMAND=/bin/cat
/etc/shadow`, wrote the shared working directory into a confirmed finding, produced
no lead from it, and then spent a later task trying to tie the burst to an SSH login
— a hypothesis that same directory refutes, since an SSH session does not land in a
web upload directory. The operand `/bin/cat` was extracted; the directory was not.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
import django  # noqa: E402

django.setup()

from agent.runtime.analysis.artifacts import extract_artifacts  # noqa: E402

_SUDO_EVENT = {
    "events": [
        {
            "_id": "3kp8gZqt29xgUPf7VD3i",
            "_source": {
                "predecoder": {"hostname": "intranet-server", "program_name": "sudo"},
                "agent": {"name": "wazuh-client", "ip": "10.35.35.206"},
                "data": {
                    "srcuser": "phopkins",
                    "dstuser": "root",
                    "command": "/bin/cat /etc/shadow",
                    "pwd": "/var/www/intranet.price.fox.org/wp-content/uploads/2022/01",
                    "tty": "pts/1",
                },
                "rule": {"id": "5402", "groups": ["syslog", "sudo"]},
            },
        }
    ]
}


def _by_kind(payload: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for artifact in extract_artifacts(json.dumps(payload)):
        out.setdefault(artifact.kind, []).append(artifact.value)
    return out


class ExecutionContextArtifactTest(unittest.TestCase):
    def test_working_directory_is_extracted_with_its_source_event(self):
        found = _by_kind(_SUDO_EVENT)
        self.assertIn("cwd", found)
        self.assertIn(
            "/var/www/intranet.price.fox.org/wp-content/uploads/2022/01", found["cwd"]
        )

    def test_working_directory_is_not_collapsed_into_file(self):
        """`file` means "what was acted on"; `cwd` means "where the actor stood".

        Merging them would put the directory beside `/bin/cat` and `/etc/shadow`,
        which is exactly the framing that made it read as an operand detail.
        """
        found = _by_kind(_SUDO_EVENT)
        self.assertNotIn(
            "/var/www/intranet.price.fox.org/wp-content/uploads/2022/01",
            found.get("file", []),
        )
        self.assertIn("/etc/shadow", found.get("file", []))

    def test_the_operands_still_extract_alongside_it(self):
        found = _by_kind(_SUDO_EVENT)
        self.assertIn("/bin/cat /etc/shadow", found.get("command", []))
        self.assertEqual(sorted(found.get("user", [])), ["phopkins", "root"])

    def test_alternate_field_spellings_resolve(self):
        for field, value in (
            ("cwd", "/tmp"),
            ("audit.cwd", "/var/tmp"),
            ("process.working_directory", "/home/svc"),
        ):
            payload = {
                "events": [
                    {"_id": "e1", "_source": {"data": {field: value}, "rule": {"id": "1"}}}
                ]
            }
            self.assertIn(value, _by_kind(payload).get("cwd", []), field)


if __name__ == "__main__":
    unittest.main(verbosity=2)
