import hashlib

from django.conf import settings
from django.db import models, transaction
from django.db.models import Max
from django.utils import timezone

from .base import TimestampedModel
from .choices import BulletinSeverity, BulletinStatus


class Bulletin(TimestampedModel):
    structure = models.ForeignKey("analyst.Structure", on_delete=models.PROTECT, related_name="bulletins")
    network = models.ForeignKey(
        "analyst.Network",
        on_delete=models.PROTECT,
        related_name="bulletins",
        null=True,
        blank=True,
    )
    external_reference = models.CharField(max_length=128, blank=True, db_index=True)
    reference_year = models.PositiveIntegerField(editable=False)
    sequence_number = models.PositiveIntegerField(editable=False)
    reference = models.CharField(max_length=80, unique=True, editable=False)
    severity = models.CharField(max_length=16, choices=BulletinSeverity.choices)
    status = models.CharField(max_length=16, choices=BulletinStatus.choices, default=BulletinStatus.DRAFT)
    ip_signature = models.CharField(max_length=64, blank=True, db_index=True, editable=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_bulletins")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="updated_bulletins")
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="deleted_bulletins",
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ("-reference_year", "-sequence_number")
        constraints = [
            models.UniqueConstraint(
                fields=("structure", "reference_year", "sequence_number"),
                name="uniq_bulletin_sequence_per_year",
            )
        ]
        indexes = [
            models.Index(fields=("structure", "ip_signature")),
            models.Index(fields=("network", "status")),
            models.Index(fields=("status",)),
        ]

    def save(self, *args, **kwargs):
        if not self.reference:
            with transaction.atomic():
                self.reference_year = timezone.localdate().year
                current = (
                    Bulletin.objects.filter(structure=self.structure, reference_year=self.reference_year)
                    .aggregate(maximum=Max("sequence_number"))["maximum"]
                    or 0
                )
                self.sequence_number = current + 1
                self.reference = f"{self.structure.code}-{self.reference_year}-{self.sequence_number:03d}"
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)

    def refresh_ip_signature(self):
        parts = sorted(f"{item.role}:{item.ip_address}:{item.port or ''}" for item in self.ip_addresses.all())
        signature = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest() if parts else ""
        if signature != self.ip_signature:
            Bulletin.objects.filter(pk=self.pk).update(ip_signature=signature)
            self.ip_signature = signature

    def __str__(self):
        return self.reference
