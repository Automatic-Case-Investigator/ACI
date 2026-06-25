from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0018_runtimeconfig_ti_cache_ttl_hours"),
    ]

    operations = [
        migrations.AddField(
            model_name="modelproviderconfig",
            name="context_length",
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
    ]
