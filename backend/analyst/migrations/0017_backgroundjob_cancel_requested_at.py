from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("analyst", "0016_rename_peer_observation_country")]

    operations = [
        migrations.AddField(
            model_name="backgroundjob",
            name="cancel_requested_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="backgroundjob",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "En attente"),
                    ("running", "En cours"),
                    ("completed", "Terminé"),
                    ("failed", "Échoué"),
                    ("canceled", "Annulé"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
    ]
