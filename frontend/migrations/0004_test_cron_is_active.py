from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0003_testip_alter_test_id_test_ip_current'),
    ]

    operations = [
        migrations.AddField(
            model_name='test',
            name='cron_is_active',
            field=models.BooleanField(default=True),
        ),
    ]
