from django.db import models

from .base import TimestampedModel
from .choices import BulletinSeverity


class RiskProfile(TimestampedModel):
    name = models.CharField(max_length=150, unique=True)
    impact = models.TextField()
    recommendation = models.TextField()
    default_severity = models.CharField(
        max_length=16,
        choices=BulletinSeverity.choices,
        default=BulletinSeverity.MEDIUM,
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)
        indexes = [
            models.Index(fields=("is_active", "name")),
            models.Index(fields=("default_severity",)),
        ]

    def __str__(self):
        return self.name
