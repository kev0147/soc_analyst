from django.db.models import Q, QuerySet
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError

from analyst.models import IPReputation
from analyst.models.choices import ReputationVerdict


ALLOWED_FLOW_ORDERING = {
    "started_at",
    "ended_at",
    "duration_seconds",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "service",
    "application",
    "direction",
    "total_bytes",
    "total_packets",
    "byte_rate",
    "packet_rate",
    "created_at",
}


def _int_param(params, name: str) -> int | None:
    value = params.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({name: "Doit être un entier."}) from exc


def _date_param(params, name: str):
    value = params.get(name)
    if value in (None, ""):
        return None
    parsed = parse_datetime(value)
    if not parsed:
        raise ValidationError({name: "Date invalide. Utilisez un format ISO-8601."})
    return parsed


def _csv_values(params, name: str) -> list[str]:
    value = params.get(name)
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _apply_ordering(queryset: QuerySet, params) -> QuerySet:
    requested = _csv_values(params, "ordering")
    if not requested:
        return queryset.order_by("-started_at", "-id")

    ordering = []
    rejected = []
    for item in requested:
        descending = item.startswith("-")
        field = item[1:] if descending else item
        if field not in ALLOWED_FLOW_ORDERING:
            rejected.append(item)
            continue
        ordering.append(f"-{field}" if descending else field)

    if rejected:
        raise ValidationError({"ordering": f"Tri non autorisé : {', '.join(rejected)}."})
    return queryset.order_by(*ordering, "-id")


def apply_flow_filters(queryset: QuerySet, params) -> QuerySet:
    queryset = queryset.select_related("network", "network__structure")

    structure_id = _int_param(params, "structure_id")
    if structure_id is not None:
        queryset = queryset.filter(network__structure_id=structure_id)

    network_id = _int_param(params, "network_id")
    if network_id is not None:
        queryset = queryset.filter(
            Q(network_id=network_id) | Q(src_network_id=network_id) | Q(dst_network_id=network_id)
        )

    import_id = _int_param(params, "import_id")
    if import_id is not None:
        queryset = queryset.filter(import_items__flow_import_id=import_id)

    started_from = _date_param(params, "started_from")
    if started_from is None:
        started_from = _date_param(params, "date_from")
    if started_from is not None:
        queryset = queryset.filter(started_at__gte=started_from)

    started_to = _date_param(params, "started_to")
    if started_to is None:
        started_to = _date_param(params, "date_to")
    if started_to is not None:
        queryset = queryset.filter(started_at__lte=started_to)

    ip = params.get("ip")
    if ip:
        queryset = queryset.filter(Q(src_ip=ip) | Q(dst_ip=ip))

    src_ip = params.get("src_ip")
    if src_ip:
        queryset = queryset.filter(src_ip=src_ip)

    dst_ip = params.get("dst_ip")
    if dst_ip:
        queryset = queryset.filter(dst_ip=dst_ip)

    port = _int_param(params, "port")
    if port is not None:
        queryset = queryset.filter(Q(src_port=port) | Q(dst_port=port))

    src_port = _int_param(params, "src_port")
    if src_port is not None:
        queryset = queryset.filter(src_port=src_port)

    dst_port = _int_param(params, "dst_port")
    if dst_port is not None:
        queryset = queryset.filter(dst_port=dst_port)

    protocol = params.get("protocol")
    if protocol:
        queryset = queryset.filter(protocol__iexact=protocol.strip())

    service = params.get("service")
    if service:
        queryset = queryset.filter(service__icontains=service.strip())

    application = params.get("application")
    if application:
        queryset = queryset.filter(application__icontains=application.strip())

    direction = params.get("direction")
    if direction:
        queryset = queryset.filter(direction=direction.strip())

    flow_id = params.get("flow_id")
    if flow_id:
        queryset = queryset.filter(sna_flow_id__icontains=flow_id.strip())

    q = params.get("q")
    if q:
        term = q.strip()
        queryset = queryset.filter(
            Q(sna_flow_id__icontains=term)
            | Q(src_ip__icontains=term)
            | Q(dst_ip__icontains=term)
            | Q(src_hostname__icontains=term)
            | Q(dst_hostname__icontains=term)
            | Q(service__icontains=term)
            | Q(application__icontains=term)
            | Q(domain__icontains=term)
        )

    min_total_bytes = _int_param(params, "min_total_bytes")
    if min_total_bytes is not None:
        queryset = queryset.filter(total_bytes__gte=min_total_bytes)

    max_total_bytes = _int_param(params, "max_total_bytes")
    if max_total_bytes is not None:
        queryset = queryset.filter(total_bytes__lte=max_total_bytes)

    min_duration_seconds = _int_param(params, "min_duration_seconds")
    if min_duration_seconds is None:
        min_duration_seconds = _int_param(params, "min_duration")
    if min_duration_seconds is not None:
        queryset = queryset.filter(duration_seconds__gte=min_duration_seconds)

    max_duration_seconds = _int_param(params, "max_duration_seconds")
    if max_duration_seconds is None:
        max_duration_seconds = _int_param(params, "max_duration")
    if max_duration_seconds is not None:
        queryset = queryset.filter(duration_seconds__lte=max_duration_seconds)

    peer_ip = params.get("peer_ip")
    if peer_ip:
        queryset = queryset.filter(Q(src_ip=peer_ip) | Q(dst_ip=peer_ip))

    peer_verdict = params.get("peer_verdict")
    malicious_peer = str(params.get("malicious_peer", "")).lower() in {"1", "true", "yes"}
    if malicious_peer:
        peer_verdict = ReputationVerdict.MALICIOUS
    if peer_verdict:
        reputation_ips = IPReputation.objects.filter(verdict=peer_verdict).values_list("ip_address", flat=True)
        queryset = queryset.filter(Q(src_ip__in=reputation_ips) | Q(dst_ip__in=reputation_ips))

    return _apply_ordering(queryset.distinct(), params)
