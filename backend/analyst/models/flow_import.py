from django.conf import settings
from django.db import models

from .choices import ImportStatus


class FlowImport(models.Model):
    network = models.ForeignKey("analyst.Network", on_delete=models.PROTECT, related_name="imports")
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="flow_imports")
    status = models.CharField(max_length=32, choices=ImportStatus.choices, default=ImportStatus.PENDING)
    original_filename = models.CharField(max_length=255)
    stored_path = models.CharField(max_length=1024)
    rejection_report_path = models.CharField(max_length=1024, blank=True)
    file_sha256 = models.CharField(max_length=64)
    file_size_bytes = models.PositiveBigIntegerField()
    detected_encoding = models.CharField(max_length=32, blank=True)
    delimiter = models.CharField(max_length=1, default=",")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    period_start = models.DateTimeField(null=True, blank=True)
    period_end = models.DateTimeField(null=True, blank=True)
    total_rows = models.PositiveBigIntegerField(default=0)
    accepted_rows = models.PositiveBigIntegerField(default=0)
    inserted_flows = models.PositiveBigIntegerField(default=0)
    reused_flows = models.PositiveBigIntegerField(default=0)
    rejected_rows = models.PositiveBigIntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ("-uploaded_at",)
        indexes = [
            models.Index(fields=("network", "uploaded_at")),
            models.Index(fields=("file_sha256",)),
            models.Index(fields=("status",)),
        ]

    def __str__(self):
        return f"{self.original_filename} — {self.get_status_display()}"

