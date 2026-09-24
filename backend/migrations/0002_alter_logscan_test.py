import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0001_initial'),
        ('frontend', '0005_test_scheduled_task_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logscan',
            name='test',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='log_scans', to='frontend.test'),
        ),
    ]
