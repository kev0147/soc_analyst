from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError


ALLOWED_OBSERVATION_ORDERING = {
    "last_seen_at",
    "first_seen_at",
    "flow_count",
    "total_bytes",
    "total_packets",
    "total_duration_seconds",
    "max_duration_seconds",
    "avg_duration_seconds",
    "host_port",
    "host_service",
    "peer_reputation__score",
    "peer_reputation__verdict",
}


def int_param(params, name: str) -> int | None:
    value = params.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({name: "Doit être un entier."}) from exc


def date_param(params, name: str):
    value = params.get(name)
    if value in (None, ""):
        return None
    parsed = parse_datetime(value)
    if not parsed:
        raise ValidationError({name: "Date invalide. Utilisez un format ISO-8601."})
    return parsed


def csv_values(params, name: str) -> list[str]:
    value = params.get(name)
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def apply_peer_observation_filters(queryset, params):
    ids = csv_values(params, "ids")
    if ids:
        try:
            queryset = queryset.filter(id__in=[int(value) for value in ids])
        except ValueError as exc:
            raise ValidationError({"ids": "Liste d'identifiants invalide."}) from exc

    network_id = int_param(params, "network_id")
    if network_id is not None:
        queryset = queryset.filter(network_id=network_id)

    structure_id = int_param(params, "structure_id")
    if structure_id is not None:
        queryset = queryset.filter(network__structure_id=structure_id)

    peer_ip = params.get("peer_ip")
    if peer_ip:
        queryset = queryset.filter(peer_reputation__ip_address=peer_ip)

    host_ip = params.get("host_ip")
    if host_ip:
        queryset = queryset.filter(host_ip=host_ip)

    host_port = int_param(params, "host_port")
    if host_port is not None:
        queryset = queryset.filter(host_port=host_port)

    port = int_param(params, "port")
    if port is not None:
        queryset = queryset.filter(host_port=port)

    service = params.get("service")
    if service:
        queryset = queryset.filter(host_service__icontains=service.strip())

    host_port_category = params.get("host_port_category")
    if host_port_category:
        queryset = queryset.filter(host_port_category__icontains=host_port_category.strip())

    verdict = params.get("verdict") or params.get("peer_verdict")
    if verdict:
        queryset = queryset.filter(peer_reputation__verdict=verdict)

    country = params.get("country")
    if country:
        queryset = queryset.filter(peer_reputation__country__iexact=country)

    date_from = date_param(params, "date_from")
    if date_from is None:
        date_from = date_param(params, "started_from")
    if date_from is not None:
        queryset = queryset.filter(last_seen_at__gte=date_from)

    date_to = date_param(params, "date_to")
    if date_to is None:
        date_to = date_param(params, "started_to")
    if date_to is not None:
        queryset = queryset.filter(first_seen_at__lte=date_to)

    min_total_bytes = int_param(params, "min_total_bytes")
    if min_total_bytes is not None:
        queryset = queryset.filter(total_bytes__gte=min_total_bytes)

    min_duration = int_param(params, "min_total_duration_seconds")
    if min_duration is None:
        min_duration = int_param(params, "min_duration_seconds")
    if min_duration is None:
        min_duration = int_param(params, "min_duration")
    if min_duration is not None:
        queryset = queryset.filter(total_duration_seconds__gte=min_duration)

    min_flow_count = int_param(params, "min_flow_count")
    if min_flow_count is not None:
        queryset = queryset.filter(flow_count__gte=min_flow_count)

    return queryset


def apply_peer_observation_ordering(queryset, params, default_ordering=None):
    requested = csv_values(params, "ordering")
    if not requested:
        return queryset.order_by(*(default_ordering or ("-last_seen_at", "-flow_count", "-total_bytes")))

    ordering = []
    rejected = []
    for item in requested:
        descending = item.startswith("-")
        field = item[1:] if descending else item
        if field not in ALLOWED_OBSERVATION_ORDERING:
            rejected.append(item)
            continue
        ordering.append(f"-{field}" if descending else field)

    if rejected:
        raise ValidationError({"ordering": f"Tri non autorisé : {', '.join(rejected)}."})
    return queryset.order_by(*ordering)
