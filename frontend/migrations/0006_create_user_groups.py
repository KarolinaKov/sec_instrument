from django.db import migrations


def create_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.get_or_create(name='senior')
    Group.objects.get_or_create(name='junior')


def remove_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name__in=['senior', 'junior']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0005_test_scheduled_task_id'),
        ('auth', '__first__'),
    ]

    operations = [
        migrations.RunPython(create_groups, remove_groups),
    ]
