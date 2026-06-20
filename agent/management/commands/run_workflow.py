"""Manually fire a workflow binding headlessly (proves the C4 trigger seam).

Usage:
    python manage.py run_workflow new_case ~247152824

This is the path a real event source (TheHive/Wazuh webhook or poller) will reuse:
event_type + case_id -> WorkflowBinding -> dispatch_run. Gated by WORKFLOWS_ENABLED.
"""
from __future__ import annotations

import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Fire a workflow binding for an event type and case id (headless)."

    def add_arguments(self, parser):
        parser.add_argument("event_type", help="e.g. new_case, new_alert")
        parser.add_argument("case_id", help="Case identifier, e.g. ~247152824")
        parser.add_argument("--payload", default="{}", help="JSON event payload (optional).")

    def handle(self, *args, **options):
        if not getattr(settings, "WORKFLOWS_ENABLED", False):
            raise CommandError(
                "Automatic workflows are disabled. Set WORKFLOWS_ENABLED=true to enable."
            )

        from agent.runtime.triggers import Trigger, fire, get_binding

        event_type = options["event_type"]
        if get_binding(event_type) is None:
            raise CommandError(f"No workflow binding registered for event '{event_type}'.")

        try:
            payload = json.loads(options["payload"])
        except json.JSONDecodeError as exc:
            raise CommandError(f"--payload is not valid JSON: {exc}")

        trigger = Trigger(event_type=event_type, case_id=options["case_id"], payload=payload)
        run = fire(trigger)
        if run is None:
            raise CommandError(f"Binding for '{event_type}' is disabled.")

        self.stdout.write(self.style.SUCCESS(
            f"workflow '{event_type}' → {run.agent_name} run {run.id} "
            f"status={run.status} error={run.error or 'none'}"
        ))
