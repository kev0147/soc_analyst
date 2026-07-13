from django.db import models

from .base import TimestampedModel
from .choices import ReputationVerdict


class IPReputation(TimestampedModel):
    ip_address = models.GenericIPAddressField(protocol="IPv4", unique=True)
    verdict = models.CharField(max_length=16, choices=ReputationVerdict.choices, default=ReputationVerdict.UNKNOWN)
    score = models.FloatField(null=True, blank=True)
    country = models.CharField(max_length=2, blank=True)
    source_count = models.PositiveSmallIntegerField(default=0)
    successful_source_count = models.PositiveSmallIntegerField(default=0)
    flow_count = models.PositiveBigIntegerField(default=0)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_analyzed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("verdict", "-score", "-last_analyzed_at", "ip_address")
        indexes = [
            models.Index(fields=("verdict", "-score")),
            models.Index(fields=("country",)),
            models.Index(fields=("source_count",)),
            models.Index(fields=("last_analyzed_at",)),
        ]

    def __str__(self):
        return f"{self.ip_address} — {self.verdict}"
