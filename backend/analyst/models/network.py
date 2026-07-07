from django.db import models

from .base import TimestampedModel


class Network(TimestampedModel):
    structure = models.ForeignKey("analyst.Structure", on_delete=models.PROTECT, related_name="networks")
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("structure__name", "name")
        constraints = [
            models.UniqueConstraint(fields=("structure", "name"), name="uniq_network_name_per_structure")
        ]

    def __str__(self):
        return f"{self.structure.code} — {self.name}"

