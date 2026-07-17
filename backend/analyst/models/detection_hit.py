from django.db import models

from .base import TimestampedModel
from .choices import BulletinSeverity, DetectionHitStatus, ReputationVerdict


class DetectionHit(TimestampedModel):
    rule = models.ForeignKey(
        "analyst.DetectionRule",
        on_delete=models.PROTECT,
        related_name="hits",
    )
    structure = models.ForeignKey(
        "analyst.Structure",
        on_delete=models.PROTECT,
        related_name="detection_hits",
    )
    network = models.ForeignKey(
        "analyst.Network",
        on_delete=models.SET_NULL,
        related_name="detection_hits",
        null=True,
        blank=True,
    )
    dedupe_key = models.CharField(max_length=64, unique=True, editable=False)
    status = models.CharField(
        max_length=16,
        choices=DetectionHitStatus.choices,
        default=DetectionHitStatus.OPEN,
    )
    severity = models.CharField(max_length=16, choices=BulletinSeverity.choices)
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    observation_date = models.DateField()
    host_ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    peer_ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    host_port = models.PositiveIntegerField(null=True, blank=True)
    peer_port = models.PositiveIntegerField(null=True, blank=True)
    service = models.CharField(max_length=128, blank=True)
    peer_country = models.CharField(max_length=255, blank=True)
    reputation_verdict = models.CharField(
        max_length=16,
        choices=ReputationVerdict.choices,
        default=ReputationVerdict.UNKNOWN,
    )
    reputation_score = models.PositiveSmallIntegerField(null=True, blank=True)
    flow_count = models.PositiveBigIntegerField(default=0)
    host_count = models.PositiveBigIntegerField(default=0)
    total_bytes = models.PositiveBigIntegerField(default=0)
    total_packets = models.PositiveBigIntegerField(default=0)
    total_duration_seconds = models.PositiveBigIntegerField(default=0)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    first_detected_at = models.DateTimeField(auto_now_add=True)
    last_detected_at = models.DateTimeField(auto_now=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-last_seen_at", "-last_detected_at")
        indexes = [
            models.Index(fields=("structure", "status", "-last_seen_at")),
            models.Index(fields=("rule", "observation_date")),
            models.Index(fields=("peer_ip", "-last_seen_at")),
            models.Index(fields=("severity", "status")),
        ]

    def __str__(self):
        return f"{self.rule.code} — {self.title}"
