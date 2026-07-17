from django.db import models


class RiskProfileIndicator(models.Model):
    risk_profile = models.ForeignKey(
        "analyst.RiskProfile",
        on_delete=models.CASCADE,
        related_name="indicator_links",
    )
    indicator = models.ForeignKey(
        "analyst.RiskIndicator",
        on_delete=models.PROTECT,
        related_name="risk_profile_links",
    )

    class Meta:
        ordering = ("risk_profile_id", "indicator_id")
        constraints = [
            models.UniqueConstraint(
                fields=("risk_profile", "indicator"),
                name="uniq_indicator_per_risk_profile",
            )
        ]

    def __str__(self):
        return f"{self.risk_profile} — {self.indicator}"
