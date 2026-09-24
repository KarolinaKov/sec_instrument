import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='test',
            name='when',
        ),
        migrations.AddField(
            model_name='test',
            name='cron',
            field=models.CharField(default='02***', max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='test',
            name='created_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='tests', to=settings.AUTH_USER_MODEL),
        ),
    ]
