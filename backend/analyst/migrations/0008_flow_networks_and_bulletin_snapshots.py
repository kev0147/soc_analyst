from django.db import migrations, models
import django.db.models.deletion


def backfill_flow_networks_and_finding_snapshots(apps, schema_editor):
    Flow = apps.get_model("analyst", "Flow")
    BulletinFinding = apps.get_model("analyst", "BulletinFinding")

    for flow in Flow.objects.all().iterator(chunk_size=1000):
        fields = []
        if flow.direction == "outbound":
            flow.src_network_id = flow.network_id
            fields.append("src_network")
        elif flow.direction == "inbound":
            flow.dst_network_id = flow.network_id
            fields.append("dst_network")
        elif flow.direction == "internal":
            flow.src_network_id = flow.network_id
            flow.dst_network_id = flow.network_id
            fields.extend(("src_network", "dst_network"))
        if fields:
            flow.save(update_fields=fields)

    findings = BulletinFinding.objects.select_related(
        "peer_observation",
        "peer_observation__network",
        "peer_observation__peer_reputation",
        "risk_profile",
    ).prefetch_related("peer_observation__peer_reputation__results")
    for finding in findings.iterator(chunk_size=500):
        observation = finding.peer_observation
        reputation = observation.peer_reputation
        risk_profile = finding.risk_profile
        finding.peer_ip_snapshot = reputation.ip_address
        finding.peer_country_snapshot = reputation.country
        finding.host_ip_snapshot = observation.host_ip
        finding.host_port_snapshot = observation.host_port
        finding.host_service_snapshot = observation.host_service
        finding.host_port_category_snapshot = observation.host_port_category
        finding.network_name_snapshot = observation.network.name
        finding.observation_first_seen_at_snapshot = observation.first_seen_at
        finding.observation_last_seen_at_snapshot = observation.last_seen_at
        finding.flow_count_snapshot = observation.flow_count
        finding.total_bytes_snapshot = observation.total_bytes
        finding.total_packets_snapshot = observation.total_packets
        finding.total_duration_seconds_snapshot = observation.total_duration_seconds
        finding.max_duration_seconds_snapshot = observation.max_duration_seconds
        finding.avg_duration_seconds_snapshot = observation.avg_duration_seconds
        finding.reputation_verdict_snapshot = reputation.verdict
        finding.reputation_score_snapshot = reputation.score
        finding.reputation_results_snapshot = [
            {
                "source": result.source,
                "status": result.status,
                "verdict": result.verdict,
                "score": result.score,
                "country": result.country,
                "analyzed_at": result.analyzed_at.isoformat(),
            }
            for result in reputation.results.all()
        ]
        finding.risk_name_snapshot = risk_profile.name
        finding.save(update_fields=(
            "peer_ip_snapshot",
            "peer_country_snapshot",
            "host_ip_snapshot",
            "host_port_snapshot",
            "host_service_snapshot",
            "host_port_category_snapshot",
            "network_name_snapshot",
            "observation_first_seen_at_snapshot",
            "observation_last_seen_at_snapshot",
            "flow_count_snapshot",
            "total_bytes_snapshot",
            "total_packets_snapshot",
            "total_duration_seconds_snapshot",
            "max_duration_seconds_snapshot",
            "avg_duration_seconds_snapshot",
            "reputation_verdict_snapshot",
            "reputation_score_snapshot",
            "reputation_results_snapshot",
            "risk_name_snapshot",
        ))


class Migration(migrations.Migration):
    dependencies = [("analyst", "0007_remove_flowimport_analyst_flo_network_b70d2e_idx_and_more")]

    operations = [
        migrations.AddField(
            model_name="flow",
            name="src_network",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="flows_as_source_network",
                to="analyst.network",
            ),
        ),
        migrations.AddField(
            model_name="flow",
            name="dst_network",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="flows_as_destination_network",
                to="analyst.network",
            ),
        ),
        migrations.AddIndex(
            model_name="flow",
            index=models.Index(fields=["src_network", "started_at"], name="flow_src_network_started_idx"),
        ),
        migrations.AddIndex(
            model_name="flow",
            index=models.Index(fields=["dst_network", "started_at"], name="flow_dst_network_started_idx"),
        ),
        migrations.AddField(
            model_name="bulletinfinding",
            name="peer_ip_snapshot",
            field=models.GenericIPAddressField(null=True, protocol="IPv4"),
        ),
        migrations.AddField(model_name="bulletinfinding", name="peer_country_snapshot", field=models.CharField(blank=True, max_length=2)),
        migrations.AddField(model_name="bulletinfinding", name="host_ip_snapshot", field=models.GenericIPAddressField(blank=True, null=True, protocol="IPv4")),
        migrations.AddField(model_name="bulletinfinding", name="host_port_snapshot", field=models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="host_service_snapshot", field=models.CharField(blank=True, max_length=128)),
        migrations.AddField(model_name="bulletinfinding", name="host_port_category_snapshot", field=models.CharField(blank=True, max_length=150)),
        migrations.AddField(model_name="bulletinfinding", name="network_name_snapshot", field=models.CharField(blank=True, max_length=255)),
        migrations.AddField(model_name="bulletinfinding", name="observation_first_seen_at_snapshot", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="observation_last_seen_at_snapshot", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="flow_count_snapshot", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="bulletinfinding", name="total_bytes_snapshot", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="bulletinfinding", name="total_packets_snapshot", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="bulletinfinding", name="total_duration_seconds_snapshot", field=models.PositiveBigIntegerField(default=0)),
        migrations.AddField(model_name="bulletinfinding", name="max_duration_seconds_snapshot", field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="avg_duration_seconds_snapshot", field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="reputation_verdict_snapshot", field=models.CharField(choices=[("malicious", "Malveillant"), ("suspicious", "Suspect"), ("clean", "Propre"), ("unknown", "Inconnu")], default="unknown", max_length=16)),
        migrations.AddField(model_name="bulletinfinding", name="reputation_score_snapshot", field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name="bulletinfinding", name="reputation_results_snapshot", field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="bulletinfinding", name="risk_name_snapshot", field=models.CharField(blank=True, max_length=150)),
        migrations.RunPython(backfill_flow_networks_and_finding_snapshots, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="bulletinfinding",
            name="peer_ip_snapshot",
            field=models.GenericIPAddressField(protocol="IPv4"),
        ),
    ]
