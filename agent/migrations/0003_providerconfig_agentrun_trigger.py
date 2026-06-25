from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agent', '0002_agentevent'),
    ]

    operations = [
        migrations.AddField(
            model_name='agentrun',
            name='trigger',
            field=models.CharField(
                choices=[
                    ('interactive', 'Interactive'),
                    ('auto', 'Automatic (workflow)'),
                    ('scheduled', 'Scheduled'),
                ],
                default='interactive',
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name='ProviderConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=64, unique=True)),
                ('kind', models.CharField(
                    choices=[
                        ('soar', 'SOAR'),
                        ('siem', 'SIEM'),
                        ('utility', 'Utility'),
                        ('filesystem', 'Filesystem'),
                    ],
                    default='utility',
                    max_length=16,
                )),
                ('enabled', models.BooleanField(default=True)),
                ('settings', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['key'],
            },
        ),
    ]
