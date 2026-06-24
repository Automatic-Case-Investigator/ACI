import os

from django.apps import AppConfig
from django.conf import settings


def _baseline_scheduler() -> None:
    """Background daemon thread: recompute behavioral baselines on a periodic interval.

    Runs inside the main server process so no external scheduler is needed.
    The interval and lookback window are tunable via Django settings:
      BASELINE_COMPUTE_INTERVAL_HOURS  (default 24)
      BASELINE_WINDOW_DAYS             (default 30)
    """
    import time

    import django.db

    # Brief startup delay so the server is fully ready before the first run.
    time.sleep(30)

    while True:
        try:
            django.db.close_old_connections()
            from agent.runtime.learning.baselines import compute_all_baselines, get_window_days

            compute_all_baselines(days=get_window_days())
        except Exception:
            pass  # never crash the scheduler thread — errors are logged inside compute_all_baselines

        from agent.runtime.config.runtime_config import baseline_interval_hours

        time.sleep(baseline_interval_hours() * 3600)


class AgentConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "agent"

    def ready(self):
        # aci_taskqueue.store reads TASKQUEUE_DB_PATH at import time; point it at the
        # same DB the agent's MCP subprocess uses before anything imports the store.
        os.environ.setdefault("TASKQUEUE_DB_PATH", settings.TASKQUEUE_DB_PATH)
        os.environ.setdefault("BOARD_DB_PATH", settings.BOARD_DB_PATH)

        # Capture logbus events into the DB for the live dashboard, and start the
        # baseline scheduler thread. Both are guarded against the autoreload child
        # and management commands that don't serve requests.
        if os.environ.get("RUN_MAIN") == "true" or not settings.DEBUG:
            from agent.dashboard.events import install

            install()

            import threading

            threading.Thread(target=_baseline_scheduler, daemon=True, name="baseline-scheduler").start()
