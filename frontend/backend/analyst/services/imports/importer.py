import csv
import os
from dataclasses import asdict
from pathlib import Path

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone

from analyst.models import Flow, FlowImport, FlowImportItem, Network
from analyst.models.choices import ImportStatus

from .csv_detector import MAX_UPLOAD_SIZE_BYTES, detect_csv
from .flow_mapper import internal_cidrs_for_network, map_sna_row
from .sna_parser import iter_rows, read_header


PREVIEW_ROWS = 20


def _import_storage_dir() -> Path:
    now = timezone.now()
    directory = Path(settings.MEDIA_ROOT) / "flow_imports" / "originals" / f"{now:%Y}" / f"{now:%m}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _rejection_storage_dir() -> Path:
    now = timezone.now()
    directory = Path(settings.MEDIA_ROOT) / "flow_imports" / "rejections" / f"{now:%Y}" / f"{now:%m}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _safe_filename(filename: str) -> str:
    base = os.path.basename(filename or "upload.csv")
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in base)


def _store_upload(uploaded_file: UploadedFile) -> Path:
    if uploaded_file.size and uploaded_file.size > MAX_UPLOAD_SIZE_BYTES:
        raise ValueError("Le fichier dépasse la limite MVP de 100 Mo.")
    target_dir = _import_storage_dir()
    target = target_dir / f"{timezone.now():%Y%m%d%H%M%S%f}_{_safe_filename(uploaded_file.name)}"
    with target.open("wb") as handle:
        for chunk in uploaded_file.chunks():
            handle.write(chunk)
    return target


def _path_for_model(path: Path) -> str:
    return str(path)


def _preview_rows(path: Path, encoding: str, delimiter: str) -> list[dict]:
    rows = []
    for row_number, row in iter_rows(path, encoding=encoding, delimiter=delimiter):
        rows.append({"row_number": row_number, "data": row})
        if len(rows) >= PREVIEW_ROWS:
            break
    return rows


@transaction.atomic
def preview_flow_import_upload(uploaded_file: UploadedFile, network: Network, user) -> dict:
    stored_path = _store_upload(uploaded_file)
    detection = detect_csv(stored_path)
    header_report = read_header(stored_path, detection.encoding, detection.delimiter)

    flow_import = FlowImport.objects.create(
        network=network,
        uploaded_by=user,
        status=ImportStatus.PENDING if header_report.is_valid else ImportStatus.FAILED,
        original_filename=uploaded_file.name,
        stored_path=_path_for_model(stored_path),
        file_sha256=detection.sha256,
        file_size_bytes=detection.size_bytes,
        detected_encoding=detection.encoding,
        delimiter=detection.delimiter,
        error_message="" if header_report.is_valid else "Colonnes obligatoires manquantes.",
    )

    return {
        "import_id": flow_import.id,
        "is_valid": header_report.is_valid,
        "file": {
            "name": flow_import.original_filename,
            "size_bytes": detection.size_bytes,
            "sha256": detection.sha256,
            "encoding": detection.encoding,
            "delimiter": detection.delimiter,
        },
        "columns": asdict(header_report),
        "preview_rows": _preview_rows(stored_path, detection.encoding, detection.delimiter) if header_report.is_valid else [],
        "errors": [] if header_report.is_valid else [{"message": "Colonnes obligatoires manquantes.", "columns": header_report.missing_required}],
    }


def _write_rejections(flow_import: FlowImport, rejected: list[dict]) -> str:
    if not rejected:
        return ""
    target = _rejection_storage_dir() / f"flow_import_{flow_import.id}_rejections.csv"
    fieldnames = ["row_number", "reason", "flow_id", "subject_ip", "peer_ip"]
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rejected)
    return _path_for_model(target)


@transaction.atomic
def confirm_flow_import(flow_import: FlowImport) -> FlowImport:
    if flow_import.status != ImportStatus.PENDING:
        raise ValueError("Seul un import en attente peut être confirmé.")

    path = Path(flow_import.stored_path)
    if not path.exists():
        raise ValueError("Le fichier original de l'import est introuvable.")

    flow_import.status = ImportStatus.PROCESSING
    flow_import.started_at = timezone.now()
    flow_import.error_message = ""
    flow_import.save(update_fields=("status", "started_at", "error_message"))

    detection = detect_csv(path)
    header_report = read_header(path, detection.encoding, detection.delimiter)
    if not header_report.is_valid:
        flow_import.status = ImportStatus.FAILED
        flow_import.error_message = "Colonnes obligatoires manquantes."
        flow_import.completed_at = timezone.now()
        flow_import.save(update_fields=("status", "error_message", "completed_at"))
        return flow_import

    internal_cidrs = internal_cidrs_for_network(flow_import.network)
    total_rows = accepted_rows = inserted_flows = reused_flows = 0
    period_start = period_end = None
    rejected: list[dict] = []

    for row_number, row in iter_rows(path, detection.encoding, detection.delimiter):
        total_rows += 1
        try:
            flow_data = map_sna_row(row, flow_import.network, internal_cidrs=internal_cidrs)
            if not flow_data["sna_flow_id"]:
                raise ValueError("Flow ID manquant.")
            defaults = {key: value for key, value in flow_data.items() if key not in {"network", "sna_flow_id"}}
            flow, created = Flow.objects.update_or_create(
                network=flow_import.network,
                sna_flow_id=flow_data["sna_flow_id"],
                defaults=defaults,
            )
            FlowImportItem.objects.get_or_create(
                flow_import=flow_import,
                flow=flow,
                defaults={"source_row_number": row_number},
            )
            accepted_rows += 1
            inserted_flows += 1 if created else 0
            reused_flows += 0 if created else 1
            started_at = flow.started_at
            period_start = started_at if period_start is None or started_at < period_start else period_start
            period_end = started_at if period_end is None or started_at > period_end else period_end
        except Exception as exc:
            rejected.append({
                "row_number": row_number,
                "reason": str(exc),
                "flow_id": row.get("Flow ID", ""),
                "subject_ip": row.get("Subject IP Address", ""),
                "peer_ip": row.get("Peer IP Address", ""),
            })

    rejection_path = _write_rejections(flow_import, rejected)
    flow_import.detected_encoding = detection.encoding
    flow_import.delimiter = detection.delimiter
    flow_import.file_sha256 = detection.sha256
    flow_import.file_size_bytes = detection.size_bytes
    flow_import.period_start = period_start
    flow_import.period_end = period_end
    flow_import.total_rows = total_rows
    flow_import.accepted_rows = accepted_rows
    flow_import.inserted_flows = inserted_flows
    flow_import.reused_flows = reused_flows
    flow_import.rejected_rows = len(rejected)
    flow_import.rejection_report_path = rejection_path
    flow_import.completed_at = timezone.now()
    flow_import.status = ImportStatus.COMPLETED_WITH_ERRORS if rejected else ImportStatus.COMPLETED
    flow_import.save()
    return flow_import
