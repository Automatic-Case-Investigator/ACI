from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0016_runtimeconfig"),
    ]

    operations = [
        migrations.AddField(
            model_name="runtimeconfig",
            name="debug_mode",
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
    ]
