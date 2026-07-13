from django.db import models

from .choices import BulletinSeverity


class BulletinFinding(models.Model):
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

    def save(self, *args, **kwargs):
        if not self.severity:
            self.severity = self.risk_profile.default_severity
        if not self.impact_snapshot:
            self.impact_snapshot = self.risk_profile.impact
        if not self.recommendation_snapshot:
            self.recommendation_snapshot = self.risk_profile.recommendation
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.bulletin} — {self.peer_observation} — {self.risk_profile}"
