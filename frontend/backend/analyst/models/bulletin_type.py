from django.db import models


class BulletinType(models.Model):
    bulletin = models.ForeignKey("analyst.Bulletin", on_delete=models.CASCADE, related_name="type_links")
    bulletin_type = models.ForeignKey(
        "analyst.BulletinTypeCatalog", on_delete=models.PROTECT, related_name="bulletin_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("bulletin", "bulletin_type"), name="uniq_type_per_bulletin")
        ]

