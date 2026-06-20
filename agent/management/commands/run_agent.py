from __future__ import annotations

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Deprecated. Use the web dashboard (`python manage.py runserver` → /dashboard/)."

    def add_arguments(self, parser):
        parser.add_argument("--agent-name", default=None)
        parser.add_argument("--case-id", default=None)
        parser.add_argument("--question", default=None)

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING(
                "manage.py run_agent is deprecated, and the interactive Textual TUI has "
                "been removed.\n\nStart the server and use the web dashboard instead:\n"
                "  python manage.py runserver\n"
                "  open http://localhost:8000/dashboard/\n\n"
                "Programmatic/headless runs still work via the REST API "
                "(POST /api/agent/runs/)."
            )
        )
