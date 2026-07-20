from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("analyst", "0017_backgroundjob_cancel_requested_at")]

    operations = [
        migrations.CreateModel(
            name="ReputationSourceState",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(choices=[("abuseipdb", "AbuseIPDB"), ("virustotal", "VirusTotal"), ("shodan", "Shodan")], max_length=32, unique=True)),
                ("quota_exhausted_until", models.DateTimeField(blank=True, null=True)),
                ("last_http_status", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("last_error_message", models.TextField(blank=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("source",)},
        ),
    ]
