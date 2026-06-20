import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AgentRun",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("case_id", models.CharField(max_length=256)),
                ("agent_name", models.CharField(max_length=64)),
                ("question", models.TextField()),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("created", "Created"),
                            ("running", "Running"),
                            ("completed", "Completed"),
                            ("incomplete_budget", "Incomplete — budget exhausted"),
                            ("cancelled", "Cancelled"),
                            ("failed", "Failed"),
                        ],
                        default="created",
                        max_length=32,
                    ),
                ),
                ("result", models.TextField(blank=True)),
                ("error", models.TextField(blank=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
