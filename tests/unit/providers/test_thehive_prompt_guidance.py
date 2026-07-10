from __future__ import annotations

import asyncio
import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-thehive"))

from aci_thehive.server import get_prompt  # noqa: E402


class TheHivePromptGuidanceTests(unittest.TestCase):
    def test_alert_wording_prefers_get_alert_first(self):
        prompt = asyncio.run(get_prompt("agent_instructions", None))
        text = prompt.messages[0].content.text
        self.assertIn("If the analyst calls\n   the id an **alert**, call `get_alert` first", text)
        self.assertIn("If the analyst calls it a **case**, or does not specify the entity type, try\n   `get_case` first", text)


if __name__ == "__main__":
    unittest.main()
