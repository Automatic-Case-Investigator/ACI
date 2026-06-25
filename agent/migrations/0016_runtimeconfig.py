from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0015_remove_workflowtriggerconfig_source_type"),
    ]

    operations = [
        migrations.CreateModel(
            name="RuntimeConfig",
            fields=[
                ("id", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("workflows_enabled", models.BooleanField(blank=True, default=None, null=True)),
                ("baseline_siem_adapter", models.CharField(blank=True, default="", max_length=64)),
                ("baseline_interval_hours", models.PositiveIntegerField(blank=True, default=None, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
