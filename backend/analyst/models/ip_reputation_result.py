from django.db import models

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

    class Meta:
        ordering = ("-analyzed_at", "source")
        constraints = [
            models.UniqueConstraint(fields=("reputation", "source"), name="uniq_reputation_result_per_source")
        ]
        indexes = [
            models.Index(fields=("source", "status")),
            models.Index(fields=("verdict", "-score")),
            models.Index(fields=("analyzed_at",)),
        ]

    def __str__(self):
        return f"{self.reputation.ip_address} — {self.source}: {self.verdict}"
