from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0009_remove_test_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='test',
            name='status',
            field=models.PositiveSmallIntegerField(
                choices=[(1, 'Normal'), (2, 'Retrying'), (3, 'Deactivated')],
                default=1,
            ),
        ),
    ]