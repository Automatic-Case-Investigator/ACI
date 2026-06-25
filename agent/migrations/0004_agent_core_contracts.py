from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0003_providerconfig_agentrun_trigger"),
    ]

    operations = [
        migrations.AlterField(
            model_name="agentrun",
            name="status",
            field=models.CharField(
                choices=[
                    ("created", "Created"),
                    ("queued", "Queued"),
                    ("running", "Running"),
                    ("waiting", "Waiting"),
                    ("completed", "Completed"),
                    ("incomplete_budget", "Incomplete — budget exhausted"),
                    ("cancelled", "Cancelled"),
                    ("blocked", "Blocked"),
                    ("failed", "Failed"),
                ],
                default="created",
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="MCPServerConfig",
            fields=[
                ("id", models.CharField(max_length=64, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=128)),
                ("transport", models.CharField(choices=[("stdio", "stdio"), ("http", "http")], max_length=16)),
                ("command_or_url", models.TextField()),
                ("env", models.JSONField(blank=True, default=dict)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "health_status",
                    models.CharField(
                        choices=[
                            ("unknown", "Unknown"),
                            ("healthy", "Healthy"),
                            ("degraded", "Degraded"),
                            ("error", "Error"),
                        ],
                        default="unknown",
                        max_length=16,
                    ),
                ),
                ("allowed_agents", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.CreateModel(
            name="ModelProviderConfig",
            fields=[
                ("id", models.CharField(default="default", max_length=64, primary_key=True, serialize=False)),
                ("base_url", models.URLField()),
                ("api_key", models.CharField(blank=True, max_length=512)),
                ("model", models.CharField(max_length=256)),
                (
                    "tool_calling_mode",
                    models.CharField(
                        choices=[("auto", "Auto"), ("native", "Native"), ("none", "None")],
                        default="auto",
                        max_length=16,
                    ),
                ),
                ("timeout", models.PositiveIntegerField(blank=True, default=None, null=True)),
                ("retry_policy", models.JSONField(blank=True, default=dict)),
                ("sampling_params", models.JSONField(blank=True, default=dict)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["id"]},
        ),
    ]
