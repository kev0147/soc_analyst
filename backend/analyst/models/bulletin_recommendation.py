from django.db import models


class BulletinRecommendation(models.Model):
    bulletin = models.ForeignKey("analyst.Bulletin", on_delete=models.CASCADE, related_name="recommendation_links")
    recommendation = models.ForeignKey(
        "analyst.RecommendationCatalog", on_delete=models.PROTECT, related_name="bulletin_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("bulletin", "recommendation"), name="uniq_recommendation_per_bulletin"
            )
        ]

