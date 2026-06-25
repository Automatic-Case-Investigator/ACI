from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent", "0005_modelproviderconfig_disable_timeout"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentevent",
            name="metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
