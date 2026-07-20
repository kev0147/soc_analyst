from django.db import models

from .base import TimestampedModel


class PeerObservation(TimestampedModel):
    peer_reputation = models.ForeignKey(
        "analyst.IPReputation",
        on_delete=models.CASCADE,
        related_name="observations",
    )
    network = models.ForeignKey(
        "analyst.Network",
        on_delete=models.PROTECT,
        related_name="peer_observations",
    )
    host_ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    host_port = models.PositiveIntegerField(null=True, blank=True)
    host_service = models.CharField(max_length=128, blank=True)
    host_port_category = models.CharField(max_length=150, blank=True)
    observed_country = models.CharField(max_length=255, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    flow_count = models.PositiveBigIntegerField(default=0)
    total_bytes = models.PositiveBigIntegerField(default=0)
    total_packets = models.PositiveBigIntegerField(default=0)
    total_duration_seconds = models.PositiveBigIntegerField(default=0)
    max_duration_seconds = models.PositiveBigIntegerField(null=True, blank=True)
    avg_duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ("-last_seen_at", "peer_reputation__ip_address", "host_ip", "host_port")
        constraints = [
            models.UniqueConstraint(
                fields=(
                    "peer_reputation",
                    "network",
                    "host_ip",
                    "host_port",
                    "host_service",
                    "host_port_category",
                ),
                name="uniq_peer_observation_endpoint",
                nulls_distinct=False,
            )
        ]
        indexes = [
            models.Index(fields=("network", "host_ip")),
            models.Index(fields=("host_port",)),
            models.Index(fields=("host_service",)),
            models.Index(fields=("-last_seen_at",)),
            models.Index(fields=("-total_duration_seconds",)),
        ]

    @property
    def peer_ip(self):
        return self.peer_reputation.ip_address

    @property
    def peer_country(self):
        return self.peer_reputation.country or self.observed_country

    def __str__(self):
        host = self.host_ip or "host inconnu"
        port = f":{self.host_port}" if self.host_port is not None else ""
        return f"{self.peer_reputation.ip_address} -> {host}{port}"
