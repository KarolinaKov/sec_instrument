import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Test',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField()),
                ('prefix', models.IntegerField()),
                ('nickname', models.CharField(max_length=255)),
                ('when', models.DateTimeField()),
                ('last_test', models.DateTimeField(blank=True, null=True)),
                ('next_scheduled', models.DateTimeField(blank=True, null=True)),
                ('when_added', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tests', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-when_added'],
            },
        ),
    ]
