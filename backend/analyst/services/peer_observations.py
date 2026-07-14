import ipaddress
from collections import defaultdict
from dataclasses import dataclass

from django.db import transaction

from analyst.models import Flow, FlowImport, IPReputation, PeerObservation
from analyst.services.imports.flow_mapper import internal_cidrs_for_structure
PORT_CATEGORIES = {
    20: "Transfert de fichiers",
    21: "Transfert de fichiers",
    22: "Administration distante",
    23: "Administration distante",
    25: "Messagerie",
    53: "DNS",
    80: "Web",
    110: "Messagerie",
    143: "Messagerie",
    443: "Web",
    445: "Partage de fichiers",
    465: "Messagerie",
    587: "Messagerie",
    993: "Messagerie",
    995: "Messagerie",
    1433: "Base de données",
    1521: "Base de données",
    3306: "Base de données",
    3389: "Administration distante",
    5432: "Base de données",
    5900: "Administration distante",
    6379: "Base de données",
    8080: "Web",
    8443: "Web",
    9200: "Base de données",
}


@dataclass(frozen=True)
class ObservationEndpoint:
    peer_ip: str
    host_ip: str
    host_port: int | None
    host_service: str
    host_port_category: str


def _flow_queryset(scope: str = "all_flows", import_id: int | None = None):
    queryset = Flow.objects.select_related("network", "network__structure").all()
    if scope == "import":
        if not import_id:
            raise ValueError("import_id est obligatoire pour scope=import.")
        FlowImport.objects.get(pk=import_id)
        queryset = queryset.filter(import_items__flow_import_id=import_id)
    elif scope != "all_flows":
        raise ValueError("scope doit valoir all_flows ou import.")
    return queryset.distinct()


def _is_internal(ip: str, cidrs) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in cidr for cidr in cidrs)


def _port_category(port: int | None, service: str = "") -> str:
    if port in PORT_CATEGORIES:
        return PORT_CATEGORIES[port]
    normalized = service.lower().strip()
    if normalized in {"http", "https", "ssl", "tls"}:
        return "Web"
    if normalized in {"ssh", "telnet", "rdp", "vnc"}:
        return "Administration distante"
    if normalized in {"smtp", "imap", "pop3"}:
        return "Messagerie"
    if normalized in {"dns"}:
        return "DNS"
    return ""


def _observation_endpoint(flow, cidrs) -> ObservationEndpoint | None:
    src_internal = _is_internal(flow.src_ip, cidrs)
    dst_internal = _is_internal(flow.dst_ip, cidrs)
    if src_internal == dst_internal:
        return None

    if src_internal:
        peer_ip = flow.dst_ip
        host_ip = flow.src_ip
        host_port = flow.src_port
    else:
        peer_ip = flow.src_ip
        host_ip = flow.dst_ip
        host_port = flow.dst_port

    host_service = flow.service or ""
    return ObservationEndpoint(
        peer_ip=peer_ip,
        host_ip=host_ip,
        host_port=host_port,
        host_service=host_service,
        host_port_category=_port_category(host_port, host_service),
    )


def _collect_stats(flows):
    stats = defaultdict(
        lambda: {
            "flow_count": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "total_duration_seconds": 0,
            "max_duration_seconds": None,
            "first_seen_at": None,
            "last_seen_at": None,
        }
    )
    cidr_cache = {}
    for flow in flows.iterator(chunk_size=1000):
        structure_id = flow.network.structure_id
        if structure_id not in cidr_cache:
            cidr_cache[structure_id] = internal_cidrs_for_structure(flow.network.structure)
        endpoint = _observation_endpoint(flow, cidr_cache[structure_id])
        if endpoint is None:
            continue
        key = (
            flow.network_id,
            endpoint.peer_ip,
            endpoint.host_ip,
            endpoint.host_port,
            endpoint.host_service,
            endpoint.host_port_category,
        )
        row = stats[key]
        row["flow_count"] += 1
        row["total_bytes"] += flow.total_bytes or 0
        row["total_packets"] += flow.total_packets or 0
        if flow.duration_seconds is not None:
            row["total_duration_seconds"] += flow.duration_seconds
            row["max_duration_seconds"] = (
                flow.duration_seconds
                if row["max_duration_seconds"] is None or flow.duration_seconds > row["max_duration_seconds"]
                else row["max_duration_seconds"]
            )
        row["first_seen_at"] = (
            flow.started_at
            if row["first_seen_at"] is None or flow.started_at < row["first_seen_at"]
            else row["first_seen_at"]
        )
        row["last_seen_at"] = (
            flow.started_at
            if row["last_seen_at"] is None or flow.started_at > row["last_seen_at"]
            else row["last_seen_at"]
        )
    return stats


def collect_peer_observation_stats(flows):
    return _collect_stats(flows)


@transaction.atomic
def sync_peer_observations(scope: str = "all_flows", import_id: int | None = None) -> dict:
    stats = _collect_stats(_flow_queryset(scope=scope, import_id=import_id))
    created = 0
    updated = 0

    for (
        network_id,
        peer_ip,
        host_ip,
        host_port,
        host_service,
        host_port_category,
    ), row in stats.items():
        reputation, _ = IPReputation.objects.get_or_create(ip_address=peer_ip)
        _, was_created = PeerObservation.objects.update_or_create(
            peer_reputation=reputation,
            network_id=network_id,
            host_ip=host_ip,
            host_port=host_port,
            host_service=host_service,
            host_port_category=host_port_category,
            defaults={
                "flow_count": row["flow_count"],
                "total_bytes": row["total_bytes"],
                "total_packets": row["total_packets"],
                "total_duration_seconds": row["total_duration_seconds"],
                "max_duration_seconds": row["max_duration_seconds"],
                "avg_duration_seconds": (
                    row["total_duration_seconds"] / row["flow_count"] if row["flow_count"] else None
                ),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
            },
        )
        if was_created:
            created += 1
        else:
            updated += 1

    return {
        "scope": scope,
        "import_id": import_id,
        "observation_count": len(stats),
        "created_count": created,
        "updated_count": updated,
    }
