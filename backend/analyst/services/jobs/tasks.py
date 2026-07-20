import os
import time

from django.conf import settings
from django.db import close_old_connections, transaction
from django.db.utils import OperationalError
from django.utils import timezone

from analyst.models import AuditEvent, BackgroundJob, FlowImport
from analyst.models.choices import BackgroundJobKind, BackgroundJobStatus, ImportStatus
from analyst.services.imports import confirm_flow_import
from analyst.services.ip_reputation import run_reputation_analysis
from analyst.services.peer_observations import sync_peer_observations
from analyst.services.daily_aggregates import build_daily_flow_aggregates
from analyst.services.detections import run_detections


def _audit(job: BackgroundJob, action: str, details: dict | None = None):
    AuditEvent.objects.create(
        actor=job.created_by,
        action=action,
        entity_type=job._meta.label_lower,
        entity_id=str(job.pk),
        details={"known_action": True, "job_kind": job.kind, **(details or {})},
    )


def _claim(job_id: str) -> BackgroundJob | None:
    with transaction.atomic():
        # PostgreSQL refuses FOR UPDATE on the nullable side of the LEFT JOINs
        # generated for created_by/flow_import. Only the BackgroundJob row needs
        # to be locked while it is claimed.
        job = (
            BackgroundJob.objects.select_for_update(of=("self",))
            .select_related("created_by", "flow_import")
            .get(pk=job_id)
        )
        if job.status != BackgroundJobStatus.QUEUED:
            return None
        job.status = BackgroundJobStatus.RUNNING
        job.started_at = timezone.now()
        job.completed_at = None
        job.error_message = ""
        job.status_message = "Démarrage"
        job.task_id = f"pid:{os.getpid()}"
        job.attempt_count += 1
        job.save(update_fields=(
            "status",
            "started_at",
            "completed_at",
            "error_message",
            "status_message",
            "task_id",
            "attempt_count",
            "updated_at",
        ))
        _audit(job, "BACKGROUND_JOB_STARTED")
    return job


def _is_database_locked(exc: OperationalError) -> bool:
    return "database is locked" in str(exc).lower() or "database table is locked" in str(exc).lower()


def _with_lock_retries(operation, *, job_id: str | None = None):
    attempts = settings.SQLITE_LOCK_RETRY_ATTEMPTS
    base_delay = settings.SQLITE_LOCK_RETRY_BASE_SECONDS
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except OperationalError as exc:
            if not _is_database_locked(exc) or attempt >= attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1))
            close_old_connections()
            time.sleep(delay)
            if job_id:
                try:
                    BackgroundJob.objects.filter(pk=job_id).update(
                        status_message=f"Base SQLite occupée — reprise {attempt + 1}/{attempts}"
                    )
                except OperationalError:
                    close_old_connections()


def _progress(job_id: str, current: int, total: int | None = None, message: str = ""):
    updates = {"progress_current": max(int(current or 0), 0)}
    if total is not None:
        updates["progress_total"] = max(int(total or 0), 0)
    if message:
        updates["status_message"] = message[:255]
    BackgroundJob.objects.filter(pk=job_id, status=BackgroundJobStatus.RUNNING).update(**updates)


def _flow_import_result(flow_import: FlowImport) -> dict:
    return {
        "import_id": flow_import.id,
        "status": flow_import.status,
        "total_rows": flow_import.total_rows,
        "accepted_rows": flow_import.accepted_rows,
        "inserted_flows": flow_import.inserted_flows,
        "reused_flows": flow_import.reused_flows,
        "rejected_rows": flow_import.rejected_rows,
    }


def _run(job: BackgroundJob) -> dict:
    if job.kind == BackgroundJobKind.FLOW_IMPORT:
        if not job.flow_import_id:
            raise ValueError("Le job d'import n'est lié à aucun import.")
        flow_import = FlowImport.objects.get(pk=job.flow_import_id)
        confirmed = confirm_flow_import(
            flow_import,
            progress_callback=lambda current, total, message: _progress(str(job.id), current, total, message),
        )
        result = _flow_import_result(confirmed)
        result["observation_sync"] = sync_peer_observations(
            scope="all_flows",
            progress_callback=lambda current, total, message: _progress(
                str(job.id), current, total, message
            ),
        )
        return result

    if job.kind == BackgroundJobKind.IP_REPUTATION:
        payload = job.payload
        return run_reputation_analysis(
            scope=payload.get("scope", "all_flows"),
            import_id=payload.get("import_id"),
            tools=payload.get("tools"),
            limit=payload.get("limit", 50),
            force_refresh=payload.get("force_refresh", False),
            progress_callback=lambda current, total, message: _progress(str(job.id), current, total, message),
        )

    if job.kind == BackgroundJobKind.DETECTION:
        return run_detections(
            job.payload,
            progress_callback=lambda current, total, message: _progress(str(job.id), current, total, message),
        )

    if job.kind == BackgroundJobKind.DAILY_AGGREGATION:
        return build_daily_flow_aggregates(
            date_from=job.payload.get("date_from"),
            date_to=job.payload.get("date_to"),
            structure_id=job.payload.get("structure_id"),
            progress_callback=lambda current, total, message: _progress(str(job.id), current, total, message),
        )

    raise ValueError(f"Type de job non pris en charge : {job.kind}.")


def _run_recoverable(job: BackgroundJob) -> dict:
    if job.kind == BackgroundJobKind.FLOW_IMPORT and job.flow_import_id:
        # Un premier passage peut avoir inséré une partie des flows avant le verrou.
        # L'import est idempotent : on le remet en attente et on reprend le CSV.
        FlowImport.objects.filter(
            pk=job.flow_import_id,
            status=ImportStatus.PROCESSING,
        ).update(status=ImportStatus.PENDING, error_message="")
    return _run(job)


def _fail(job: BackgroundJob, exc: Exception):
    message = str(exc)[:4000] or exc.__class__.__name__
    completed_at = timezone.now()
    with transaction.atomic():
        BackgroundJob.objects.filter(pk=job.pk).update(
            status=BackgroundJobStatus.FAILED,
            error_message=message,
            status_message="Échec",
            completed_at=completed_at,
        )
        if job.kind == BackgroundJobKind.FLOW_IMPORT and job.flow_import_id:
            FlowImport.objects.filter(pk=job.flow_import_id).update(
                status=ImportStatus.FAILED,
                error_message=message,
                completed_at=completed_at,
            )
        _audit(job, "BACKGROUND_JOB_FAILED", {"error": message})
    job.refresh_from_db()


def _complete(job: BackgroundJob, result: dict):
    completed_at = timezone.now()
    with transaction.atomic():
        BackgroundJob.objects.filter(pk=job.pk).update(
            status=BackgroundJobStatus.COMPLETED,
            result=result,
            error_message="",
            status_message="Terminé",
            progress_current=models_progress_total(job.pk),
            completed_at=completed_at,
        )
        _audit(job, "BACKGROUND_JOB_COMPLETED", {"result": result})
    job.refresh_from_db()


def execute_background_job(job_id: str) -> dict | None:
    job = _with_lock_retries(lambda: _claim(job_id), job_id=job_id)
    if job is None:
        return None
    try:
        result = _with_lock_retries(lambda: _run_recoverable(job), job_id=job_id)
    except Exception as exc:
        _with_lock_retries(lambda: _fail(job, exc), job_id=job_id)
        raise

    _with_lock_retries(lambda: _complete(job, result), job_id=job_id)
    return result


def fail_interrupted_jobs() -> int:
    jobs = list(
        BackgroundJob.objects.select_related("created_by", "flow_import").filter(
            status=BackgroundJobStatus.RUNNING
        )
    )
    for job in jobs:
        _with_lock_retries(
            lambda job=job: _fail(job, RuntimeError("Le worker précédent a été interrompu pendant ce traitement.")),
            job_id=str(job.id),
        )
    return len(jobs)


def models_progress_total(job_id) -> int:
    return BackgroundJob.objects.values_list("progress_total", flat=True).get(pk=job_id)
