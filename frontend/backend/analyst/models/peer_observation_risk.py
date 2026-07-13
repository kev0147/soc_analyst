from django.db import models

from .choices import BulletinSeverity


class PeerObservationRisk(models.Model):
    peer_observation = models.ForeignKey(
        "analyst.PeerObservation",
        on_delete=models.CASCADE,
        related_name="risk_links",
    )
    risk_profile = models.ForeignKey(
        "analyst.RiskProfile",
        on_delete=models.PROTECT,
        related_name="observation_links",
    )
    severity = models.CharField(max_length=16, choices=BulletinSeverity.choices, blank=True)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("peer_observation", "risk_profile"),
                name="uniq_risk_profile_per_peer_observation",
            )
        ]
        indexes = [models.Index(fields=("severity",))]

    def save(self, *args, **kwargs):
        if not self.severity:
            self.severity = self.risk_profile.default_severity
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.peer_observation} — {self.risk_profile}"
