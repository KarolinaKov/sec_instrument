from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0006_create_user_groups'),
    ]

    operations = [
        migrations.AddField(
            model_name='test',
            name='hostname',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
    ]
