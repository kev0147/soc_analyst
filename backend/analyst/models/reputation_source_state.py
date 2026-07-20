from django.db import models

from .choices import ReputationSource


class ReputationSourceState(models.Model):
    source = models.CharField(max_length=32, choices=ReputationSource.choices, unique=True)
    quota_exhausted_until = models.DateTimeField(null=True, blank=True)
    last_http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    last_error_message = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("source",)

    def __str__(self):
        return self.source
