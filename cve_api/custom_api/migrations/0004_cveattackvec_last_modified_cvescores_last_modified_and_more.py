# Generated by Django 4.2.14 on 2024-08-12 14:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("custom_api", "0003_alter_cveattackvec_table_alter_cvescores_table_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="cveattackvec",
            name="last_modified",
            field=models.DateTimeField(default="2021-01-01 00:00:00"),
        ),
        migrations.AddField(
            model_name="cvescores",
            name="last_modified",
            field=models.DateTimeField(default="2021-01-01 00:00:00"),
        ),
        migrations.AddField(
            model_name="cveseverity",
            name="last_modified",
            field=models.DateTimeField(default="2021-01-01 00:00:00"),
        ),
    ]
