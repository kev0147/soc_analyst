from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("analyst", "0019_default_generic_risk_profile"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="bulletinfinding",
            index=models.Index(fields=["peer_ip_snapshot"], name="analyst_bul_peer_ip_7ea2c8_idx"),
        ),
    ]
