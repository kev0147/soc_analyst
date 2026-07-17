from django.db import models


class RiskProfilePortService(models.Model):
    risk_profile = models.ForeignKey(
        "analyst.RiskProfile",
        on_delete=models.CASCADE,
        related_name="port_services",
    )
    port = models.PositiveIntegerField()
    service = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("port", "service")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(port__lte=65535),
                name="risk_profile_port_lte_65535",
            ),
            models.UniqueConstraint(
                fields=("risk_profile", "port", "service"),
                name="uniq_port_service_per_risk_profile",
            ),
        ]
        indexes = [models.Index(fields=("port", "service"))]

    def __str__(self):
        return f"{self.port}/{self.service or '-'} — {self.risk_profile}"
