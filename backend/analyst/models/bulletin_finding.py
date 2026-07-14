from django.db import models

from .choices import BulletinSeverity, ReputationSource, ReputationVerdict


class BulletinFinding(models.Model):
    SNAPSHOT_FIELDS = (
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
        "impact_snapshot",
        "recommendation_snapshot",
    )
    bulletin = models.ForeignKey(
        "analyst.Bulletin",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    peer_observation = models.ForeignKey(
        "analyst.PeerObservation",
        on_delete=models.PROTECT,
        related_name="bulletin_findings",
    )
    risk_profile = models.ForeignKey(
        "analyst.RiskProfile",
        on_delete=models.PROTECT,
        related_name="bulletin_findings",
    )
    severity = models.CharField(max_length=16, choices=BulletinSeverity.choices, blank=True)
    peer_ip_snapshot = models.GenericIPAddressField(protocol="IPv4")
    peer_country_snapshot = models.CharField(max_length=2, blank=True)
    host_ip_snapshot = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    host_port_snapshot = models.PositiveIntegerField(null=True, blank=True)
    host_service_snapshot = models.CharField(max_length=128, blank=True)
    host_port_category_snapshot = models.CharField(max_length=150, blank=True)
    network_name_snapshot = models.CharField(max_length=255, blank=True)
    observation_first_seen_at_snapshot = models.DateTimeField(null=True, blank=True)
    observation_last_seen_at_snapshot = models.DateTimeField(null=True, blank=True)
    flow_count_snapshot = models.PositiveBigIntegerField(default=0)
    total_bytes_snapshot = models.PositiveBigIntegerField(default=0)
    total_packets_snapshot = models.PositiveBigIntegerField(default=0)
    total_duration_seconds_snapshot = models.PositiveBigIntegerField(default=0)
    max_duration_seconds_snapshot = models.PositiveBigIntegerField(null=True, blank=True)
    avg_duration_seconds_snapshot = models.FloatField(null=True, blank=True)
    reputation_verdict_snapshot = models.CharField(
        max_length=16,
        choices=ReputationVerdict.choices,
        default=ReputationVerdict.UNKNOWN,
    )
    reputation_score_snapshot = models.FloatField(null=True, blank=True)
    reputation_results_snapshot = models.JSONField(default=list, blank=True)
    risk_name_snapshot = models.CharField(max_length=150, blank=True)
    impact_snapshot = models.TextField(blank=True)
    recommendation_snapshot = models.TextField(blank=True)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("bulletin", "peer_observation", "risk_profile"),
                name="uniq_finding_per_bulletin_observation_risk",
            )
        ]
        indexes = [models.Index(fields=("severity",))]

    def capture_snapshot(self):
        observation = self.peer_observation
        reputation = observation.peer_reputation
        self.peer_ip_snapshot = reputation.ip_address
        self.peer_country_snapshot = reputation.country
        self.host_ip_snapshot = observation.host_ip
        self.host_port_snapshot = observation.host_port
        self.host_service_snapshot = observation.host_service
        self.host_port_category_snapshot = observation.host_port_category
        self.network_name_snapshot = observation.network.name
        self.observation_first_seen_at_snapshot = observation.first_seen_at
        self.observation_last_seen_at_snapshot = observation.last_seen_at
        self.flow_count_snapshot = observation.flow_count
        self.total_bytes_snapshot = observation.total_bytes
        self.total_packets_snapshot = observation.total_packets
        self.total_duration_seconds_snapshot = observation.total_duration_seconds
        self.max_duration_seconds_snapshot = observation.max_duration_seconds
        self.avg_duration_seconds_snapshot = observation.avg_duration_seconds
        self.reputation_verdict_snapshot = reputation.verdict
        self.reputation_score_snapshot = reputation.score
        self.reputation_results_snapshot = [
            {
                "source": result.source,
                "status": result.status,
                "verdict": result.verdict,
                "score": result.score,
                "country": result.country,
                "analyzed_at": result.analyzed_at.isoformat(),
                "expires_at": result.expires_at.isoformat() if result.expires_at else None,
                "freshness_status": result.freshness_status,
            }
            for result in reputation.results.filter(
                source__in=(ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL)
            ).order_by("source")
        ]
        self.risk_name_snapshot = self.risk_profile.name
        self.severity = self.severity or self.risk_profile.default_severity
        self.impact_snapshot = self.impact_snapshot or self.risk_profile.impact
        self.recommendation_snapshot = self.recommendation_snapshot or self.risk_profile.recommendation

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.capture_snapshot()
        else:
            original = type(self).objects.only(
                "peer_observation_id",
                "risk_profile_id",
                *self.SNAPSHOT_FIELDS,
            ).get(pk=self.pk)
            if (
                original.peer_observation_id != self.peer_observation_id
                or original.risk_profile_id != self.risk_profile_id
            ):
                raise ValueError("L'observation et le profil de risque d'un constat existant sont immuables.")
            for field in self.SNAPSHOT_FIELDS:
                setattr(self, field, getattr(original, field))
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.bulletin} — {self.peer_ip_snapshot} — {self.risk_name_snapshot}"
