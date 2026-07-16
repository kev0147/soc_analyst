from django.db.models import Q
from rest_framework.exceptions import ValidationError

from analyst.models import Flow, FlowImport, IPReputation
from analyst.models.choices import ReputationVerdict
from analyst.services.flows import apply_flow_filters


ALLOWED_ORDERING = {
    "host_ip",
    "total_bytes",
    "total_duration_seconds",
    "flow_count",
    "malicious_peer_count",
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

    peer_port_filter = _integer(params, "peer_port", minimum=0)
    if peer_port_filter is not None and peer_port_filter > 65535:
        raise ValidationError({"peer_port": "Le port doit être compris entre 0 et 65535."})
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
        peer_port = flow.src_port if src_is_malicious else flow.dst_port
        host_port = flow.dst_port if src_is_malicious else flow.src_port
        reputation = reputations[peer_ip]
        country = reputation.country.upper()

        if host_filter and host_ip != host_filter:
            continue
        if peer_filter and peer_ip != peer_filter:
            continue
        if country_filter and country != country_filter:
            continue
        if peer_port_filter is not None and peer_port != peer_port_filter:
            continue

        total_bytes = flow.total_bytes or 0
        duration = flow.duration_seconds or 0
        row = rows.setdefault(
            host_ip,
            {
                "host_ip": host_ip,
                "flow_count": 0,
                "total_bytes": 0,
                "total_duration_seconds": 0,
                "first_seen_at": None,
                "last_seen_at": None,
                "peer_ports": set(),
                "host_ports": set(),
                "countries": set(),
                "peers": {},
            },
        )
        row["flow_count"] += 1
        row["total_bytes"] += total_bytes
        row["total_duration_seconds"] += duration
        if peer_port is not None:
            row["peer_ports"].add(peer_port)
        if host_port is not None:
            row["host_ports"].add(host_port)
        if country:
            row["countries"].add(country)
        if row["first_seen_at"] is None or flow.started_at < row["first_seen_at"]:
            row["first_seen_at"] = flow.started_at
        if row["last_seen_at"] is None or flow.started_at > row["last_seen_at"]:
            row["last_seen_at"] = flow.started_at

        peer = row["peers"].setdefault(
            peer_ip,
            {
                "ip_address": peer_ip,
                "country": reputation.country,
                "score": reputation.score,
                "ports": set(),
                "host_ports": set(),
                "services": set(),
                "flow_count": 0,
                "total_bytes": 0,
                "total_duration_seconds": 0,
                "first_seen_at": None,
                "last_seen_at": None,
            },
        )
        peer["flow_count"] += 1
        peer["total_bytes"] += total_bytes
        peer["total_duration_seconds"] += duration
        if peer_port is not None:
            peer["ports"].add(peer_port)
        if host_port is not None:
            peer["host_ports"].add(host_port)
        if flow.service:
            peer["services"].add(flow.service)
        if peer["first_seen_at"] is None or flow.started_at < peer["first_seen_at"]:
            peer["first_seen_at"] = flow.started_at
        if peer["last_seen_at"] is None or flow.started_at > peer["last_seen_at"]:
            peer["last_seen_at"] = flow.started_at

    results = []
    for row in rows.values():
        if min_total_bytes is not None and row["total_bytes"] < min_total_bytes:
            continue
        if min_duration is not None and row["total_duration_seconds"] < min_duration:
            continue
        peers = []
        for peer in row["peers"].values():
            peers.append({
                **{key: value for key, value in peer.items() if key not in {"ports", "host_ports", "services"}},
                "ports": sorted(peer["ports"]),
                "host_ports": sorted(peer["host_ports"]),
                "services": sorted(peer["services"]),
                "first_seen_at": peer["first_seen_at"].isoformat() if peer["first_seen_at"] else None,
                "last_seen_at": peer["last_seen_at"].isoformat() if peer["last_seen_at"] else None,
            })
        peers.sort(key=lambda item: (item["total_bytes"], item["total_duration_seconds"]), reverse=True)
        results.append({
            "host_ip": row["host_ip"],
            "malicious_peer_count": len(peers),
            "malicious_peers": peers,
            "countries": sorted(row["countries"]),
            "peer_ports": sorted(row["peer_ports"]),
            "host_ports": sorted(row["host_ports"]),
            "flow_count": row["flow_count"],
            "total_bytes": row["total_bytes"],
            "total_duration_seconds": row["total_duration_seconds"],
            "first_seen_at": row["first_seen_at"].isoformat() if row["first_seen_at"] else None,
            "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
        })

    results.sort(key=lambda row: row[ordering_field], reverse=descending)
    return {
        "scope": scope,
        "ordering": ordering,
        "count": len(results),
        "totals": {
            "hosts": len(results),
            "malicious_peers": len({peer["ip_address"] for row in results for peer in row["malicious_peers"]}),
            "flows": sum(row["flow_count"] for row in results),
            "total_bytes": sum(row["total_bytes"] for row in results),
            "total_duration_seconds": sum(row["total_duration_seconds"] for row in results),
        },
        "results": results,
    }
