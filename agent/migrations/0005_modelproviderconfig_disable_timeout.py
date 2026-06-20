from django.db import migrations, models


def clear_default_timeout(apps, schema_editor):
    ModelProviderConfig = apps.get_model("agent", "ModelProviderConfig")
    ModelProviderConfig.objects.filter(timeout=60).update(timeout=None)


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0004_agent_core_contracts"),
    ]

    operations = [
        migrations.AlterField(
            model_name="modelproviderconfig",
            name="timeout",
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(clear_default_timeout, migrations.RunPython.noop),
    ]
