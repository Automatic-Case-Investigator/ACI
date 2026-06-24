"""Management command: compute behavioral baselines from Wazuh event data."""
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Compute behavioral baselines for Wazuh users and endpoints."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Lookback window in days (default: 30).",
        )
        parser.add_argument(
            "--subject-type",
            choices=["endpoint", "user", "all"],
            default="all",
            help="Limit computation to a specific subject type (default: all).",
        )
        parser.add_argument(
            "--subject-id",
            default=None,
            help="Target a single subject by ID, skipping discovery.",
        )

    def handle(self, *args, **options):
        from agent.runtime.learning.baselines import compute_all_baselines

        try:
            written, skipped = compute_all_baselines(
                days=options["days"],
                subject_type=options["subject_type"],
                subject_id=options["subject_id"],
            )
        except Exception as exc:
            raise CommandError(f"Baseline computation failed: {exc}") from exc

        self.stdout.write(
            self.style.SUCCESS(f"Done: {written} feature(s) written, {skipped} skipped.")
        )
