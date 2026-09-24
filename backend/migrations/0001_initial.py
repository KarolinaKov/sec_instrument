import django.contrib.postgres.fields
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('frontend', '0003_testip_alter_test_id_test_ip_current'),
    ]

    operations = [
        migrations.CreateModel(
            name='LogScan',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.CharField(choices=[('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], default='running', max_length=20)),
                ('timestamp_start', models.DateTimeField(default=django.utils.timezone.now)),
                ('timestamp_end', models.DateTimeField(blank=True, null=True)),
                ('live_ips_now', django.contrib.postgres.fields.ArrayField(base_field=models.GenericIPAddressField(), default=list, help_text='Live IPs found during this scan', size=None)),
                ('succeeded', models.IntegerField(default=0, help_text='Number of successful scans')),
                ('unsucceeded', models.IntegerField(default=0, help_text='Number of failed scans')),
                ('problematic_ips', django.contrib.postgres.fields.ArrayField(base_field=models.GenericIPAddressField(), default=list, help_text='IPs where scan failed', size=None)),
                ('vulnerabilities', models.IntegerField(default=0, help_text='Total vulnerabilities found')),
                ('vulners', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=500), default=list, help_text='List of vulnerabilities found', size=None)),
                ('path_to_file', models.CharField(blank=True, help_text='Path to comprehensive scan output', max_length=500)),
                ('consecutive_failures', models.IntegerField(default=0, help_text='Track consecutive failures for this test')),
                ('test', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='log_scans', to='frontend.test')),
            ],
            options={
                'ordering': ['-timestamp_start'],
            },
        ),
        migrations.CreateModel(
            name='LogScanRetry',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('reason_to_retry', models.IntegerField(choices=[(1, 'DifferentIP'), (2, 'SmallFail'), (3, 'BigFail')])),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scheduled_for', models.DateTimeField(help_text='When the retry is scheduled')),
                ('celery_task_id', models.CharField(blank=True, help_text='Celery task ID for tracking', max_length=255)),
                ('executed', models.BooleanField(default=False)),
                ('log_scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='retries', to='backend.logscan')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='logscan',
            index=models.Index(fields=['test', '-timestamp_start'], name='backend_log_test_id_928e0c_idx'),
        ),
        migrations.AddIndex(
            model_name='logscan',
            index=models.Index(fields=['status'], name='backend_log_status_8dc7aa_idx'),
        ),
        migrations.AddIndex(
            model_name='logscanretry',
            index=models.Index(fields=['log_scan', '-created_at'], name='backend_log_log_sca_748b25_idx'),
        ),
        migrations.AddIndex(
            model_name='logscanretry',
            index=models.Index(fields=['scheduled_for', 'executed'], name='backend_log_schedul_3847f2_idx'),
        ),
    ]
