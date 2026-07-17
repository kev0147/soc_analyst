from django.db import models

from .base import TimestampedModel
from .choices import BulletinSeverity, DetectionRuleType


class DetectionRule(TimestampedModel):
    code = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)
    rule_type = models.CharField(max_length=40, choices=DetectionRuleType.choices)
    severity = models.CharField(max_length=16, choices=BulletinSeverity.choices)
    parameters = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name", "id")
        indexes = [
            models.Index(fields=("is_active", "rule_type")),
            models.Index(fields=("severity", "is_active")),
        ]

    def __str__(self):
        return self.name
