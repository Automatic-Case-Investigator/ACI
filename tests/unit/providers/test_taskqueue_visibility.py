from __future__ import annotations

import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-taskqueue"))

os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["ACI_CASE_ID"] = "~case"
os.environ["ACI_RUN_ID"] = "run-1"
os.environ["ACI_AGENT_NAME"] = "triage"

from aci_taskqueue import store  # noqa: E402


class TaskqueueVisibilityTest(unittest.TestCase):
    def setUp(self):
        store.init_db()

    def test_agent_payload_omits_queue_lifecycle_timestamps(self):
        stored = store.create_task(
            "~case", "run-1", "triage",
            title="Triage case ~case",
            description="Use case date as incident time.",
            priority=100,
        )
        created = store.agent_visible_task(stored)

        self.assertIn("created_at", stored)
        self.assertNotIn("created_at", created)
        self.assertNotIn("updated_at", created)
        self.assertNotIn("claimed_at", created)

        claimed = store.agent_visible_task(store.claim_next("~case", "run-1", "triage"))
        self.assertEqual(claimed["id"], created["id"])
        self.assertNotIn("created_at", claimed)
        self.assertNotIn("updated_at", claimed)
        self.assertNotIn("claimed_at", claimed)

        listed = store.agent_visible_tasks(store.list_tasks("~case", "run-1", "triage"))[0]
        self.assertEqual(listed["id"], created["id"])
        self.assertNotIn("created_at", listed)
        self.assertNotIn("updated_at", listed)
        self.assertNotIn("claimed_at", listed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
