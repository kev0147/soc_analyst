from django.conf import settings
from django.db import models

from .base import TimestampedModel


class BulletinResponse(TimestampedModel):
    bulletin = models.ForeignKey("analyst.Bulletin", on_delete=models.CASCADE, related_name="responses")
    respondent_name = models.CharField(max_length=255)
    respondent_email = models.EmailField(blank=True)
    received_at = models.DateTimeField()
    content = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="bulletin_responses")

    class Meta:
        ordering = ("-received_at",)
        indexes = [models.Index(fields=("bulletin", "received_at"))]

