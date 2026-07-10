from __future__ import annotations

import unittest
from unittest.mock import patch

from benchmark.pipeline import load_wazuh


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = str(self._payload)

    def json(self):
        return self._payload


class WazuhTeardownTest(unittest.TestCase):
    def test_elasticdump_command_wraps_windows_cmd_file(self):
        with patch.object(load_wazuh.shutil, "which", side_effect=[
            r"C:\Users\acezxn\AppData\Roaming\npm\elasticdump.cmd",
            None,
            None,
        ]), patch.object(load_wazuh.os, "name", "nt"), \
                patch.dict(load_wazuh.os.environ, {"COMSPEC": r"C:\Windows\System32\cmd.exe"}):
            cmd = load_wazuh._elasticdump_command(["--type=data"])

        self.assertEqual(cmd[:3], [
            r"C:\Windows\System32\cmd.exe",
            "/c",
            r"C:\Users\acezxn\AppData\Roaming\npm\elasticdump.cmd",
        ])
        self.assertEqual(cmd[3:], ["--type=data"])

    def test_teardown_retries_429_delete_by_query(self):
        post_responses = [
            _Response(429, headers={"retry-after": "0"}),
            _Response(200, {"task": "node:123"}),
        ]
        get_responses = [
            _Response(200, {
                "completed": False,
                "task": {"status": {"total": 123, "deleted": 50, "batches": 1}},
            }),
            _Response(200, {
                "completed": True,
                "task": {"status": {"total": 123, "deleted": 123, "batches": 2}},
                "response": {"deleted": 123, "failures": []},
            }),
        ]
        calls = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            return post_responses.pop(0)

        def fake_get(_url, **_kwargs):
            return get_responses.pop(0)

        with patch("httpx.post", side_effect=fake_post), \
                patch("httpx.get", side_effect=fake_get), \
                patch.object(load_wazuh.time, "sleep"):
            result = load_wazuh.teardown(
                "https://admin:secret@localhost:9201",
                "fox",
                max_retries=2,
                poll_interval=0,
            )

        self.assertEqual(result["deleted"], 123)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["task_attempts"], 2)
        self.assertEqual(len(calls), 2)
        # teardown is a bulk cleanup: unthrottled + server-side parallel across shards
        self.assertIn("requests_per_second=-1", calls[0][0])
        self.assertIn("slices=auto", calls[0][0])
        self.assertIn("scroll_size=500", calls[0][0])
        self.assertIn("wait_for_completion=false", calls[0][0])

    def test_teardown_returns_error_after_repeated_429s(self):
        def fake_post(_url, **_kwargs):
            return _Response(429, headers={"retry-after": "0"})

        with patch("httpx.post", side_effect=fake_post), patch.object(load_wazuh.time, "sleep"):
            result = load_wazuh.teardown(
                "https://admin:secret@localhost:9201",
                "fox",
                max_retries=1,
            )

        self.assertEqual(result["status_code"], 429)
        self.assertEqual(result["attempts"], 2)
        self.assertIn("rerun teardown", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
