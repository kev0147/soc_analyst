import csv
import ipaddress
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone

from analyst.models import Flow, FlowImport, FlowImportItem, Network, Structure
from analyst.models.choices import ImportStatus

from .csv_detector import MAX_UPLOAD_SIZE_BYTES, detect_csv
from .flow_mapper import endpoint_ips_for_row, map_sna_row
from .sna_parser import iter_rows, read_header


PREVIEW_ROWS = 20


def _structure_cidr_index(structure: Structure) -> list[tuple[ipaddress.IPv4Network, Network]]:
    entries = [
        (ipaddress.ip_network(cidr.cidr, strict=False), cidr.network)
        for network in structure.networks.filter(is_active=True).prefetch_related("cidrs")
        for cidr in network.cidrs.all()
    ]
    entries.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return entries


def _network_for_ip(ip_value: str, cidr_index: list[tuple[ipaddress.IPv4Network, Network]]) -> Network | None:
    if not ip_value:
        return None
    address = ipaddress.ip_address(ip_value)
    matches = [(cidr, network) for cidr, network in cidr_index if address in cidr]
    if not matches:
        return None
    best_prefix = matches[0][0].prefixlen
    best_networks = {network.id: network for cidr, network in matches if cidr.prefixlen == best_prefix}
    if len(best_networks) > 1:
        raise ValueError(f"L'IP {ip_value} correspond à plusieurs réseaux avec le même préfixe CIDR.")
    return next(iter(best_networks.values()))


def _network_for_row(row: dict[str, str], cidr_index: list[tuple[ipaddress.IPv4Network, Network]]) -> Network:
    subject_ip, peer_ip = endpoint_ips_for_row(row)
    subject_network = _network_for_ip(subject_ip, cidr_index)
    peer_network = _network_for_ip(peer_ip, cidr_index)
    if subject_network and peer_network and subject_network.id != peer_network.id:
        raise ValueError("Les deux IP internes appartiennent à des réseaux différents de la structure.")
    network = subject_network or peer_network
    if network is None:
        raise ValueError("Aucune IP ne correspond aux CIDR internes de la structure.")
    return network


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
def preview_flow_import_upload(uploaded_file: UploadedFile, structure: Structure, user) -> dict:
    stored_path = _store_upload(uploaded_file)
    detection = detect_csv(stored_path)
    header_report = read_header(stored_path, detection.encoding, detection.delimiter)

    flow_import = FlowImport.objects.create(
        structure=structure,
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

    preview_rows = _preview_rows(stored_path, detection.encoding, detection.delimiter) if header_report.is_valid else []
    cidr_index = _structure_cidr_index(structure)
    if header_report.is_valid and not cidr_index:
        flow_import.status = ImportStatus.FAILED
        flow_import.error_message = "La structure ne possède aucun CIDR sur un réseau actif."
        flow_import.save(update_fields=("status", "error_message"))
        raise ValueError(flow_import.error_message)

    detected_networks = Counter()
    sample_rejections = []
    for preview_row in preview_rows:
        try:
            network = _network_for_row(preview_row["data"], cidr_index)
            detected_networks[network.id] += 1
        except (ValueError, TypeError) as exc:
            sample_rejections.append({"row_number": preview_row["row_number"], "reason": str(exc)})

    network_names = {
        network.id: network.name
        for network in structure.networks.filter(id__in=detected_networks.keys())
    }
    return {
        "import_id": flow_import.id,
        "structure": {"id": structure.id, "code": structure.code, "name": structure.name},
        "is_valid": header_report.is_valid,
        "file": {
            "name": flow_import.original_filename,
            "size_bytes": detection.size_bytes,
            "sha256": detection.sha256,
            "encoding": detection.encoding,
            "delimiter": detection.delimiter,
        },
        "columns": asdict(header_report),
        "preview_rows": preview_rows,
        "network_detection": {
            "networks": [
                {"network_id": network_id, "name": network_names[network_id], "sample_rows": count}
                for network_id, count in detected_networks.items()
            ],
            "sample_rejections": sample_rejections,
        },
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

    cidr_index = _structure_cidr_index(flow_import.structure)
    if not cidr_index:
        raise ValueError("La structure ne possède aucun CIDR sur un réseau actif.")
    internal_cidrs = tuple(cidr for cidr, _network in cidr_index)
    total_rows = accepted_rows = inserted_flows = reused_flows = 0
    period_start = period_end = None
    rejected: list[dict] = []

    for row_number, row in iter_rows(path, detection.encoding, detection.delimiter):
        total_rows += 1
        try:
            network = _network_for_row(row, cidr_index)
            flow_data = map_sna_row(row, network, internal_cidrs=internal_cidrs)
            if not flow_data["sna_flow_id"]:
                raise ValueError("Flow ID manquant.")
            defaults = {key: value for key, value in flow_data.items() if key not in {"network", "sna_flow_id"}}
            flow, created = Flow.objects.update_or_create(
                network=network,
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
                "flow_id": row.get("Flow ID") or row.get("id", ""),
                "subject_ip": row.get("Subject IP Address") or row.get("searchSubject.ipAddress", ""),
                "peer_ip": row.get("Peer IP Address") or row.get("peer.ipAddress", ""),
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
