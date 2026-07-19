from django.db import models


class BulletinActivity(models.Model):
    bulletin = models.ForeignKey(
        "analyst.Bulletin",
        on_delete=models.CASCADE,
        related_name="activity_links",
    )
    activity = models.ForeignKey(
        "analyst.ActivityCatalog",
        on_delete=models.PROTECT,
        related_name="bulletin_links",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("bulletin", "activity"),
                name="uniq_activity_per_bulletin",
            )
        ]

    def __str__(self):
        return f"{self.bulletin} — {self.activity}"
