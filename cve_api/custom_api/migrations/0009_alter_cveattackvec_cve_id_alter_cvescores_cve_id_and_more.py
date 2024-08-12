# Generated by Django 4.2.14 on 2024-08-12 15:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("custom_api", "0008_remove_cvefact_cves_attack_vectors_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cveattackvec",
            name="cve_id",
            field=models.IntegerField(unique=True),
        ),
        migrations.AlterField(
            model_name="cvescores",
            name="cve_id",
            field=models.IntegerField(unique=True),
        ),
        migrations.AlterField(
            model_name="cveseverity",
            name="cve_id",
            field=models.IntegerField(unique=True),
        ),
    ]