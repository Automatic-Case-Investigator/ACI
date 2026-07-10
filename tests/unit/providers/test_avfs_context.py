from __future__ import annotations

import unittest
from unittest.mock import patch

from agent.runtime.infra.avfs import bind_agent_id, home_dir, reset_agent_id, sessions_dir


class AVFSContextTest(unittest.TestCase):
    def test_bound_agent_id_drives_paths_without_provider_lookup(self):
        token = bind_agent_id("bound-agent")
        try:
            self.assertEqual(home_dir(), "/home/bound-agent")
            self.assertEqual(sessions_dir(), "/home/bound-agent/sessions")
        finally:
            reset_agent_id(token)

    def test_provider_resolved_agent_id_does_not_use_orm_in_async_context(self):
        import asyncio
        try:
            from agent.runtime.providers import avfs
        except ModuleNotFoundError as exc:
            if exc.name == "django":
                self.skipTest("Django not installed in this lightweight test environment")
            raise

        async def run():
            avfs.cache_agent_id("cached-agent")
            with patch("agent.runtime.config.resolve_settings") as resolve_settings:
                self.assertEqual(avfs.resolved_agent_id(), "cached-agent")
                resolve_settings.assert_not_called()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main(verbosity=2)
