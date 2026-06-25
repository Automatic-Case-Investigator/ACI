from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0017_runtimeconfig_debug_mode"),
    ]

    operations = [
        migrations.AddField(
            model_name="runtimeconfig",
            name="ti_cache_ttl_hours",
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
    ]
