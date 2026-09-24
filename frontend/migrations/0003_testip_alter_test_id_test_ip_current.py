import django.contrib.postgres.fields
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0002_remove_test_when_test_cron_alter_test_created_by'),
    ]

    operations = [
        migrations.CreateModel(
            name='TestIP',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('ip_address', django.contrib.postgres.fields.ArrayField(base_field=models.GenericIPAddressField(), default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AlterField(
            model_name='test',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AddField(
            model_name='test',
            name='ip_current',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='current_for', to='frontend.testip'),
        ),
    ]
