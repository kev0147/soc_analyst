from django.db.models import Q
from rest_framework.exceptions import ValidationError

from analyst.models import Flow, FlowImport, IPReputation
from analyst.models.choices import ReputationVerdict
from analyst.services.flows import apply_flow_filters


ALLOWED_ORDERING = {
    "host_ip",
    "malicious_ip",
    "reputation_score",
    "total_bytes",
    "total_duration_seconds",
    "flow_count",
    "last_seen_at",
}


def _integer(params, name: str, *, minimum: int | None = None) -> int | None:
    value = params.get(name)
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({name: "Doit être un entier."}) from exc
    if minimum is not None and parsed < minimum:
        raise ValidationError({name: f"Doit être supérieur ou égal à {minimum}."})
    return parsed


def _scoped_flows(params):
    scope = params.get("scope") or "structure"
    flow_params = {}
    if scope == "structure":
        structure_id = _integer(params, "structure_id", minimum=1)
        if structure_id is None:
            raise ValidationError({"structure_id": "Ce champ est obligatoire pour ce périmètre."})
        flow_params["structure_id"] = structure_id
    elif scope == "import":
        import_id = _integer(params, "import_id", minimum=1)
        if import_id is None:
            raise ValidationError({"import_id": "Ce champ est obligatoire pour ce périmètre."})
        if not FlowImport.objects.filter(pk=import_id).exists():
            raise ValidationError({"import_id": "Import introuvable."})
        flow_params["import_id"] = import_id
    elif scope == "date_range":
        date_from = params.get("date_from")
        date_to = params.get("date_to")
        if not date_from or not date_to:
            raise ValidationError({"date_range": "Les dates de début et de fin sont obligatoires."})
        flow_params.update({"date_from": date_from, "date_to": date_to})
    else:
        raise ValidationError({"scope": "Valeur attendue : structure, import ou date_range."})

    return scope, apply_flow_filters(Flow.objects.all(), flow_params).order_by()


def malicious_communications(params) -> dict:
    scope, flows = _scoped_flows(params)
    ordering = params.get("ordering") or "-total_bytes"
    descending = ordering.startswith("-")
    ordering_field = ordering[1:] if descending else ordering
    if ordering_field not in ALLOWED_ORDERING:
        raise ValidationError({"ordering": "Tri non autorisé."})

    host_port_filter = _integer(params, "host_port", minimum=0)
    if host_port_filter is not None and host_port_filter > 65535:
        raise ValidationError({"host_port": "Le port doit être compris entre 0 et 65535."})
    min_total_bytes = _integer(params, "min_total_bytes", minimum=0)
    min_duration = _integer(params, "min_total_duration_seconds", minimum=0)
    host_filter = (params.get("host_ip") or "").strip()
    peer_filter = (params.get("peer_ip") or "").strip()
    country_filter = (params.get("country") or "").strip().upper()

    reputations = {
        item.ip_address: item
        for item in IPReputation.objects.filter(verdict=ReputationVerdict.MALICIOUS)
    }
    malicious_ips = set(reputations)
    rows = {}
    relevant_flows = flows.filter(Q(src_ip__in=malicious_ips) | Q(dst_ip__in=malicious_ips))

    for flow in relevant_flows.iterator(chunk_size=1000):
        src_is_malicious = flow.src_ip in malicious_ips
        dst_is_malicious = flow.dst_ip in malicious_ips
        if src_is_malicious == dst_is_malicious:
            continue

        peer_ip = flow.src_ip if src_is_malicious else flow.dst_ip
        host_ip = flow.dst_ip if src_is_malicious else flow.src_ip
        host_port = flow.dst_port if src_is_malicious else flow.src_port
        peer_port = flow.src_port if src_is_malicious else flow.dst_port
        peer_location = flow.src_location if src_is_malicious else flow.dst_location
        reputation = reputations[peer_ip]
        country = (reputation.country or peer_location or "").strip()

        if host_filter and host_ip != host_filter:
            continue
        if peer_filter and peer_ip != peer_filter:
            continue
        if country_filter and country.upper() != country_filter:
            continue
        if host_port_filter is not None and host_port != host_port_filter:
            continue

        total_bytes = flow.total_bytes or 0
        duration = flow.duration_seconds or 0
        row = rows.setdefault(
            (host_ip, peer_ip),
            {
                "host_ip": host_ip,
                "host_ports": set(),
                "malicious_ip": peer_ip,
                "reputation_verdict": reputation.verdict,
                "reputation_score": reputation.score,
                "peer_country": country,
                "peer_ports": set(),
                "services": set(),
                "flow_count": 0,
                "total_bytes": 0,
                "total_duration_seconds": 0,
                "first_seen_at": None,
                "last_seen_at": None,
            },
        )
        row["flow_count"] += 1
        row["total_bytes"] += total_bytes
        row["total_duration_seconds"] += duration
        if not row["peer_country"] and country:
            row["peer_country"] = country
        if peer_port is not None:
            row["peer_ports"].add(peer_port)
        if host_port is not None:
            row["host_ports"].add(host_port)
        if flow.service:
            row["services"].add(flow.service)
        if row["first_seen_at"] is None or flow.started_at < row["first_seen_at"]:
            row["first_seen_at"] = flow.started_at
        if row["last_seen_at"] is None or flow.started_at > row["last_seen_at"]:
            row["last_seen_at"] = flow.started_at

    results = []
    for row in rows.values():
        if min_total_bytes is not None and row["total_bytes"] < min_total_bytes:
            continue
        if min_duration is not None and row["total_duration_seconds"] < min_duration:
            continue
        results.append({
            **{key: value for key, value in row.items() if key not in {"host_ports", "peer_ports", "services"}},
            "host_ports": sorted(row["host_ports"]),
            "peer_ports": sorted(row["peer_ports"]),
            "services": sorted(row["services"]),
            "first_seen_at": row["first_seen_at"].isoformat() if row["first_seen_at"] else None,
            "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
        })

    results.sort(
        key=lambda row: row[ordering_field] if row[ordering_field] is not None else -1,
        reverse=descending,
    )
    return {
        "scope": scope,
        "ordering": ordering,
        "count": len(results),
        "totals": {
            "hosts": len({row["host_ip"] for row in results}),
            "malicious_peers": len({row["malicious_ip"] for row in results}),
            "correlations": len(results),
            "flows": sum(row["flow_count"] for row in results),
            "total_bytes": sum(row["total_bytes"] for row in results),
            "total_duration_seconds": sum(row["total_duration_seconds"] for row in results),
        },
        "results": results,
    }
