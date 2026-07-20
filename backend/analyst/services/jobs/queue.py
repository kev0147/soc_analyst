from django.db import transaction

from analyst.models import BackgroundJob
from analyst.models.choices import BackgroundJobKind, BackgroundJobStatus, ImportStatus


ACTIVE_STATUSES = (BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING)


def enqueue_background_job(
    *,
    kind: str,
    payload: dict,
    user,
    flow_import=None,
    retried_from=None,
) -> tuple[BackgroundJob, bool]:
    if not retried_from:
        active = BackgroundJob.objects.filter(kind=kind, status__in=ACTIVE_STATUSES)
        if flow_import is not None:
            active = active.filter(flow_import=flow_import)
        else:
            active = active.filter(payload=payload)
        existing = active.first()
        if existing:
            return existing, False

    with transaction.atomic():
        job = BackgroundJob.objects.create(
            kind=kind,
            payload=payload,
            created_by=user,
            flow_import=flow_import,
            retried_from=retried_from,
            status_message="En attente d'un worker",
        )
    return job, True


def retry_background_job(job: BackgroundJob, user) -> BackgroundJob:
    if job.status not in (BackgroundJobStatus.FAILED, BackgroundJobStatus.CANCELED):
        raise ValueError("Seul un job échoué ou annulé peut être relancé.")

    if job.kind == BackgroundJobKind.FLOW_IMPORT and job.flow_import_id:
        flow_import = job.flow_import
        flow_import.status = ImportStatus.PENDING
        flow_import.started_at = None
        flow_import.completed_at = None
        flow_import.error_message = ""
        flow_import.save(update_fields=("status", "started_at", "completed_at", "error_message"))

    retried, _ = enqueue_background_job(
        kind=job.kind,
        payload=job.payload,
        user=user,
        flow_import=job.flow_import,
        retried_from=job,
    )
    return retried
