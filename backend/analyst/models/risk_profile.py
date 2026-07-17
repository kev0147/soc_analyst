from django.db import models

from .base import TimestampedModel
from .choices import BulletinSeverity


class RiskProfile(TimestampedModel):
    activity = models.CharField(max_length=150, blank=True, db_index=True)
    name = models.CharField(max_length=150)
    impact = models.TextField()
    recommendation = models.TextField()
    source_key = models.CharField(max_length=64, unique=True, null=True, blank=True, editable=False)
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
