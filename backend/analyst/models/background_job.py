import uuid

from django.conf import settings
from django.db import models

from .choices import BackgroundJobKind, BackgroundJobStatus


class BackgroundJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=32, choices=BackgroundJobKind.choices)
    status = models.CharField(
        max_length=16,
        choices=BackgroundJobStatus.choices,
        default=BackgroundJobStatus.QUEUED,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="background_jobs",
    )
    flow_import = models.ForeignKey(
        "analyst.FlowImport",
        on_delete=models.CASCADE,
        related_name="background_jobs",
        null=True,
        blank=True,
    )
    retried_from = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="retries",
        null=True,
        blank=True,
    )
    task_id = models.CharField(max_length=64, blank=True, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    status_message = models.CharField(max_length=255, blank=True)
    progress_current = models.PositiveBigIntegerField(default=0)
    progress_total = models.PositiveBigIntegerField(default=0)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    cancel_requested_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("status", "created_at")),
            models.Index(fields=("kind", "created_at")),
            models.Index(fields=("flow_import", "created_at")),
        ]

    @property
    def progress_percent(self):
        if self.status == BackgroundJobStatus.COMPLETED:
            return 100
        if not self.progress_total:
            return None
        return min(round(self.progress_current * 100 / self.progress_total, 1), 100)

    @property
    def can_retry(self):
        return self.status in (BackgroundJobStatus.FAILED, BackgroundJobStatus.CANCELED)

    @property
    def can_cancel(self):
        return self.status in (BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING) and not self.cancel_requested_at

    def __str__(self):
        return f"{self.get_kind_display()} — {self.get_status_display()}"
