from django.db import models

from .base import TimestampedModel


class RiskIndicator(TimestampedModel):
    name = models.TextField(unique=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name
