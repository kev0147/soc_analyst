from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("analyst", "0015_alter_bulletinfinding_peer_country_snapshot_and_more"),
    ]

    operations = [
        migrations.RenameField(
            model_name="peerobservation",
            old_name="peer_country",
            new_name="observed_country",
        ),
    ]
