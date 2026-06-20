import os

from django.apps import AppConfig
from django.conf import settings


class AgentConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "agent"

    def ready(self):
        # aci_taskqueue.store reads TASKQUEUE_DB_PATH at import time; point it at the
        # same DB the agent's MCP subprocess uses before anything imports the store.
        os.environ.setdefault("TASKQUEUE_DB_PATH", settings.TASKQUEUE_DB_PATH)
        os.environ.setdefault("BOARD_DB_PATH", settings.BOARD_DB_PATH)

        # Capture logbus events into the DB for the live dashboard. Guarded against
        # the autoreload child / management commands that don't serve requests.
        if os.environ.get("RUN_MAIN") == "true" or not settings.DEBUG:
            from agent.dashboard.events import install

            install()
