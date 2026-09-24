from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0004_test_cron_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='test',
            name='scheduled_task_id',
            field=models.CharField(blank=True, default='', help_text='Celery task ID of the currently pending one-shot vulnerability scan, if any', max_length=255),
        ),
    ]
