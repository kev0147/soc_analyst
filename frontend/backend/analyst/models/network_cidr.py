import ipaddress

from django.core.exceptions import ValidationError
from django.db import models


class NetworkCIDR(models.Model):
    network = models.ForeignKey("analyst.Network", on_delete=models.CASCADE, related_name="cidrs")
    cidr = models.CharField(max_length=18)
    label = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("network", "cidr")
        constraints = [
            models.UniqueConstraint(fields=("network", "cidr"), name="uniq_cidr_per_network")
        ]

    def clean(self):
        try:
            parsed = ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as exc:
            raise ValidationError({"cidr": "CIDR invalide."}) from exc
        if parsed.version != 4:
            raise ValidationError({"cidr": "Le MVP accepte uniquement IPv4."})
        self.cidr = str(parsed)

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.cidr} ({self.label})" if self.label else self.cidr

