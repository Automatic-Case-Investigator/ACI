from __future__ import annotations

"""Tunables and cache keys shared by the per-task tool loop."""

import json
import re


_QUEUE_CONTEXT_MAX_TASKS = 12


_QUEUE_CONTEXT_SNIPPET_CHARS = 120


# Per-task tool-call cap. A single task is not allowed to consume the whole run's
# budget: in a diagnosed live run one gap-check task spent 88 of ~100 calls, starving
# every later (higher-value) task. When a task reaches this many tool calls, `think`
# strips its tools and forces a wrap-up so the loop advances to the next task with
# whatever was found. Tuned well below the typical run budget so several tasks get a
# fair share, yet high enough that a legitimately deep task still completes.
_MAX_TASK_TOOL_CALLS = 50


_SIEM_TIME_WINDOW_TOOLS = frozenset(
    {
        "search",
        "search_keyword",
        "profile_field",
        "get_event_volume",
        "correlate_entity",
        "correlate_techniques",
    }
)


_CACHEABLE_READ_TOOLS = frozenset(
    {
        "get_case",
        "get_alert",
        "list_case_alerts",
        "get_event",
        "get_event_volume",
        "profile_field",
        "search",
        "search_keyword",
    }
)


_TASK_WINDOW_RE = re.compile(
    r"Time window:\s*`?([0-9T:.\-+Z]+)`?\s+to\s+`?([0-9T:.\-+Z]+)`?",
    re.IGNORECASE,
)


def _tool_cache_key(name: str, args: dict) -> str:
    return json.dumps({"tool": name, "args": args}, sort_keys=True, default=str)
