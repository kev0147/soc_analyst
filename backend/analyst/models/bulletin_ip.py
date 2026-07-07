from django.db import models

from .choices import BulletinIPRole


class BulletinIP(models.Model):
    bulletin = models.ForeignKey("analyst.Bulletin", on_delete=models.CASCADE, related_name="ip_addresses")
    ip_address = models.GenericIPAddressField(protocol="IPv4")
    role = models.CharField(max_length=16, choices=BulletinIPRole.choices)

    class Meta:
        ordering = ("role", "ip_address")
        constraints = [
            models.UniqueConstraint(fields=("bulletin", "ip_address"), name="uniq_ip_per_bulletin")
        ]
        indexes = [models.Index(fields=("ip_address",))]

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.bulletin.refresh_ip_signature()

    def delete(self, *args, **kwargs):
        bulletin = self.bulletin
        result = super().delete(*args, **kwargs)
        bulletin.refresh_ip_signature()
        return result

