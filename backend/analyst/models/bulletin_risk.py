from django.db import models


class BulletinRisk(models.Model):
    bulletin = models.ForeignKey("analyst.Bulletin", on_delete=models.CASCADE, related_name="risk_links")
    risk = models.ForeignKey("analyst.RiskCatalog", on_delete=models.PROTECT, related_name="bulletin_links")

    class Meta:
        constraints = [models.UniqueConstraint(fields=("bulletin", "risk"), name="uniq_risk_per_bulletin")]

