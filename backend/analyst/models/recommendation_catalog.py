from django.db import models

from .base import TimestampedModel


class RecommendationCatalog(TimestampedModel):
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

