import ipaddress

from django.db import models

from .choices import EndpointRole, FlowDirection, MappingMethod


class Flow(models.Model):
    network = models.ForeignKey("analyst.Network", on_delete=models.CASCADE, related_name="flows")
    sna_flow_id = models.CharField(max_length=128)
    domain = models.CharField(max_length=255, blank=True)
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveBigIntegerField(null=True, blank=True)
    flow_action = models.CharField(max_length=128, blank=True)
    mapping_method = models.CharField(max_length=32, choices=MappingMethod.choices)
    direction = models.CharField(max_length=16, choices=FlowDirection.choices)

    src_ip = models.GenericIPAddressField(protocol="IPv4")
    src_hostname = models.CharField(max_length=255, blank=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    src_role = models.CharField(max_length=16, choices=EndpointRole.choices, default=EndpointRole.UNKNOWN)
    src_location = models.CharField(max_length=255, blank=True)
    src_asn = models.PositiveBigIntegerField(null=True, blank=True)
    src_asn_assignment = models.CharField(max_length=255, blank=True)
    src_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    src_packets = models.PositiveBigIntegerField(null=True, blank=True)

    dst_ip = models.GenericIPAddressField(protocol="IPv4")
    dst_hostname = models.CharField(max_length=255, blank=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    dst_role = models.CharField(max_length=16, choices=EndpointRole.choices, default=EndpointRole.UNKNOWN)
    dst_location = models.CharField(max_length=255, blank=True)
    dst_asn = models.PositiveBigIntegerField(null=True, blank=True)
    dst_asn_assignment = models.CharField(max_length=255, blank=True)
    dst_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    dst_packets = models.PositiveBigIntegerField(null=True, blank=True)

    conversation_ip_a = models.GenericIPAddressField(protocol="IPv4", editable=False)
    conversation_ip_b = models.GenericIPAddressField(protocol="IPv4", editable=False)
    protocol = models.CharField(max_length=32, blank=True)
    service = models.CharField(max_length=128, blank=True)
    application = models.CharField(max_length=255, blank=True)
    appliance = models.CharField(max_length=255, blank=True)
    byte_rate = models.FloatField(null=True, blank=True)
    packet_rate = models.FloatField(null=True, blank=True)
    total_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    total_packets = models.PositiveBigIntegerField(null=True, blank=True)
    tcp_connections = models.PositiveBigIntegerField(null=True, blank=True)
    tcp_retransmissions = models.PositiveBigIntegerField(null=True, blank=True)
    tcp_retransmission_ratio = models.FloatField(null=True, blank=True)
    actions = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-started_at",)
        constraints = [
            models.UniqueConstraint(fields=("network", "sna_flow_id"), name="uniq_sna_flow_per_network")
        ]
        indexes = [
            models.Index(fields=("network", "started_at")),
            models.Index(fields=("src_ip", "started_at")),
            models.Index(fields=("dst_ip", "started_at")),
            models.Index(fields=("direction", "started_at")),
            models.Index(fields=("protocol",)),
            models.Index(fields=("src_port",)),
            models.Index(fields=("dst_port",)),
            models.Index(fields=("conversation_ip_a", "conversation_ip_b", "started_at")),
        ]

    def save(self, *args, **kwargs):
        endpoints = sorted((self.src_ip, self.dst_ip), key=lambda value: int(ipaddress.ip_address(value)))
        self.conversation_ip_a, self.conversation_ip_b = endpoints
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port or '-'} → {self.dst_ip}:{self.dst_port or '-'}"

