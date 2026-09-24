from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0009_remove_test_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='test',
            name='ip_current',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name='current_for',
                to='frontend.testip',
            ),
        ),
    ]