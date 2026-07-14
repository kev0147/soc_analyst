import os

from django.db import transaction
from django.utils import timezone

from analyst.models import AuditEvent, BackgroundJob, FlowImport
from analyst.models.choices import BackgroundJobKind, BackgroundJobStatus, ImportStatus
from analyst.services.imports import confirm_flow_import
from analyst.services.ip_reputation import run_reputation_analysis


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
        job = BackgroundJob.objects.select_for_update().select_related("created_by", "flow_import").get(pk=job_id)
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
        return _flow_import_result(confirmed)

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

    raise ValueError(f"Type de job non pris en charge : {job.kind}.")


def _fail(job: BackgroundJob, exc: Exception):
    message = str(exc)[:4000] or exc.__class__.__name__
    completed_at = timezone.now()
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
    job.refresh_from_db()
    _audit(job, "BACKGROUND_JOB_FAILED", {"error": message})


def execute_background_job(job_id: str) -> dict | None:
    job = _claim(job_id)
    if job is None:
        return None
    try:
        result = _run(job)
    except Exception as exc:
        _fail(job, exc)
        raise

    completed_at = timezone.now()
    BackgroundJob.objects.filter(pk=job.pk).update(
        status=BackgroundJobStatus.COMPLETED,
        result=result,
        error_message="",
        status_message="Terminé",
        progress_current=models_progress_total(job.pk),
        completed_at=completed_at,
    )
    job.refresh_from_db()
    _audit(job, "BACKGROUND_JOB_COMPLETED", {"result": result})
    return result


def fail_interrupted_jobs() -> int:
    jobs = list(
        BackgroundJob.objects.select_related("created_by", "flow_import").filter(
            status=BackgroundJobStatus.RUNNING
        )
    )
    for job in jobs:
        _fail(job, RuntimeError("Le worker précédent a été interrompu pendant ce traitement."))
    return len(jobs)


def models_progress_total(job_id) -> int:
    return BackgroundJob.objects.values_list("progress_total", flat=True).get(pk=job_id)
