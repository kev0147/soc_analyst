from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("analyst", "0020_bulletinfinding_peer_ip_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="peerobservation",
            name="protocols",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="bulletinfinding",
            name="protocols_snapshot",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
