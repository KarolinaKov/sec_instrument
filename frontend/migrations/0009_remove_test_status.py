from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0008_test_vulnerability_alert_settings'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='test',
            name='status',
        ),
    ]