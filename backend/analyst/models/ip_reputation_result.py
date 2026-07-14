from django.db import models
from django.utils import timezone

from .choices import ReputationSource, ReputationStatus, ReputationVerdict


class IPReputationResult(models.Model):
    reputation = models.ForeignKey("analyst.IPReputation", on_delete=models.CASCADE, related_name="results")
    source = models.CharField(max_length=32, choices=ReputationSource.choices)
    status = models.CharField(max_length=16, choices=ReputationStatus.choices, default=ReputationStatus.SUCCESS)
    verdict = models.CharField(max_length=16, choices=ReputationVerdict.choices, default=ReputationVerdict.UNKNOWN)
    score = models.FloatField(null=True, blank=True)
    country = models.CharField(max_length=2, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    analyzed_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-analyzed_at", "source")
        constraints = [
            models.UniqueConstraint(fields=("reputation", "source"), name="uniq_reputation_result_per_source")
        ]
        indexes = [
            models.Index(fields=("source", "status")),
            models.Index(fields=("verdict", "-score")),
            models.Index(fields=("analyzed_at",)),
            models.Index(fields=("source", "expires_at")),
        ]

    @property
    def is_stale(self):
        return self.expires_at is None or self.expires_at <= timezone.now()

    @property
    def freshness_status(self):
        if self.status == ReputationStatus.ERROR:
            return "error" if not self.is_stale else "stale"
        if self.status == ReputationStatus.SKIPPED:
            return "unavailable" if not self.is_stale else "stale"
        return "stale" if self.is_stale else "fresh"

    def __str__(self):
        return f"{self.reputation.ip_address} — {self.source}: {self.verdict}"
