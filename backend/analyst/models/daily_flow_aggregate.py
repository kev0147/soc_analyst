from django.db import models

from .base import TimestampedModel
from .choices import FlowDirection, ReputationVerdict


class DailyFlowAggregate(TimestampedModel):
    date = models.DateField()
    structure = models.ForeignKey(
        "analyst.Structure",
        on_delete=models.PROTECT,
        related_name="daily_flow_aggregates",
    )
    network = models.ForeignKey(
        "analyst.Network",
        on_delete=models.PROTECT,
        related_name="daily_flow_aggregates",
    )
    dedupe_key = models.CharField(max_length=64, unique=True, editable=False)
    host_ip = models.GenericIPAddressField(protocol="IPv4")
    peer_ip = models.GenericIPAddressField(protocol="IPv4")
    host_port = models.PositiveIntegerField(null=True, blank=True)
    peer_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=32, blank=True)
    service = models.CharField(max_length=128, blank=True)
    direction = models.CharField(max_length=16, choices=FlowDirection.choices)
    peer_country = models.CharField(max_length=255, blank=True)
    reputation_verdict = models.CharField(
        max_length=16,
        choices=ReputationVerdict.choices,
        default=ReputationVerdict.UNKNOWN,
    )
    reputation_score = models.PositiveSmallIntegerField(null=True, blank=True)
    flow_count = models.PositiveBigIntegerField(default=0)
    total_bytes = models.PositiveBigIntegerField(default=0)
    total_packets = models.PositiveBigIntegerField(default=0)
    total_duration_seconds = models.PositiveBigIntegerField(default=0)
    max_duration_seconds = models.PositiveBigIntegerField(null=True, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-date", "structure_id", "host_ip", "peer_ip")
        indexes = [
            models.Index(fields=("structure", "date")),
            models.Index(fields=("network", "date")),
            models.Index(fields=("peer_ip", "date")),
            models.Index(fields=("host_ip", "date")),
            models.Index(fields=("reputation_verdict", "date")),
        ]

    def __str__(self):
        return f"{self.date} — {self.host_ip} / {self.peer_ip}"
