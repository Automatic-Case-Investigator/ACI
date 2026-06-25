from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0014_baselinecomputeconfig"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="workflowtriggerconfig",
            name="source_type",
        ),
    ]
