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
    peer_country: str


def _flow_queryset(scope: str = "all_flows", import_id: int | None = None):
    queryset = Flow.objects.select_related("network", "network__structure").only(
        "network_id",
        "network__structure_id",
        "network__structure__id",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "src_location",
        "dst_location",
        "service",
        "total_bytes",
        "total_packets",
        "duration_seconds",
        "started_at",
    )
    if scope == "import":
        if not import_id:
            raise ValueError("import_id est obligatoire pour scope=import.")
        FlowImport.objects.get(pk=import_id)
        queryset = queryset.filter(import_items__flow_import_id=import_id).distinct()
    elif scope != "all_flows":
        raise ValueError("scope doit valoir all_flows ou import.")
    return queryset


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
        peer_country = flow.dst_location
        host_ip = flow.src_ip
        host_port = flow.src_port
    else:
        peer_ip = flow.src_ip
        peer_country = flow.src_location
        host_ip = flow.dst_ip
        host_port = flow.dst_port

    host_service = flow.service or ""
    return ObservationEndpoint(
        peer_ip=peer_ip,
        host_ip=host_ip,
        host_port=host_port,
        host_service=host_service,
        host_port_category=_port_category(host_port, host_service),
        peer_country=(peer_country or "").strip(),
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
        if endpoint.peer_country and not row.get("peer_country"):
            row["peer_country"] = endpoint.peer_country
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


def _chunks(items, size=500):
    items = list(items)
    for offset in range(0, len(items), size):
        yield items[offset : offset + size]


def _reputations_by_ip(peer_ips: set[str]) -> dict[str, IPReputation]:
    # SQLite limite le nombre de variables dans une requête IN. Les lectures et
    # créations sont donc volontairement découpées en lots portables.
    for peer_ip_chunk in _chunks(sorted(peer_ips)):
        IPReputation.objects.bulk_create(
            [IPReputation(ip_address=peer_ip) for peer_ip in peer_ip_chunk],
            ignore_conflicts=True,
            batch_size=500,
        )

    reputations = {}
    for peer_ip_chunk in _chunks(sorted(peer_ips)):
        reputations.update(
            IPReputation.objects.filter(ip_address__in=peer_ip_chunk).in_bulk(field_name="ip_address")
        )
    return reputations


def sync_peer_observations(
    scope: str = "all_flows",
    import_id: int | None = None,
    progress_callback=None,
    batch_size: int = 500,
) -> dict:
    # PeerObservation est un agrégat global et durable. Un recalcul limité à un
    # import écraserait les totaux issus des imports précédents pour le même
    # couple peer/hôte/port. Le scope demandé reste retourné à titre de contexte,
    # mais la matérialisation est toujours reconstruite depuis les flows uniques.
    if scope not in {"all_flows", "import"}:
        raise ValueError("scope doit valoir all_flows ou import.")
    if scope == "import":
        if not import_id:
            raise ValueError("import_id est obligatoire pour scope=import.")
        FlowImport.objects.get(pk=import_id)
    stats = _collect_stats(_flow_queryset(scope="all_flows"))
    total = len(stats)
    if progress_callback:
        progress_callback(0, total, f"Préparation de {total} observations")

    reputations = _reputations_by_ip({key[1] for key in stats})
    existing = {
        (
            item.peer_reputation_id,
            item.network_id,
            item.host_ip,
            item.host_port,
            item.host_service,
            item.host_port_category,
        ): item
        for item in PeerObservation.objects.all().iterator(chunk_size=batch_size)
    }
    to_create = []
    to_update = []
    update_fields = (
        "observed_country",
        "flow_count",
        "total_bytes",
        "total_packets",
        "total_duration_seconds",
        "max_duration_seconds",
        "avg_duration_seconds",
        "first_seen_at",
        "last_seen_at",
    )

    for key, row in stats.items():
        network_id, peer_ip, host_ip, host_port, host_service, host_port_category = key
        reputation = reputations[peer_ip]
        observation_key = (
            reputation.id,
            network_id,
            host_ip,
            host_port,
            host_service,
            host_port_category,
        )
        observation = existing.get(observation_key) or PeerObservation(
            peer_reputation=reputation,
            network_id=network_id,
            host_ip=host_ip,
            host_port=host_port,
            host_service=host_service,
            host_port_category=host_port_category,
        )
        observation.observed_country = row.get("peer_country", "")
        observation.flow_count = row["flow_count"]
        observation.total_bytes = row["total_bytes"]
        observation.total_packets = row["total_packets"]
        observation.total_duration_seconds = row["total_duration_seconds"]
        observation.max_duration_seconds = row["max_duration_seconds"]
        observation.avg_duration_seconds = (
            row["total_duration_seconds"] / row["flow_count"] if row["flow_count"] else None
        )
        observation.first_seen_at = row["first_seen_at"]
        observation.last_seen_at = row["last_seen_at"]
        (to_update if observation.pk else to_create).append(observation)

    processed = 0
    for chunk in _chunks(to_create, batch_size):
        with transaction.atomic():
            PeerObservation.objects.bulk_create(chunk, batch_size=batch_size)
        processed += len(chunk)
        if progress_callback:
            progress_callback(processed, total, "Création des observations")
    for chunk in _chunks(to_update, batch_size):
        with transaction.atomic():
            PeerObservation.objects.bulk_update(chunk, update_fields, batch_size=batch_size)
        processed += len(chunk)
        if progress_callback:
            progress_callback(processed, total, "Mise à jour des observations")

    return {
        "scope": scope,
        "import_id": import_id,
        "aggregation_scope": "all_flows",
        "observation_count": len(stats),
        "created_count": len(to_create),
        "updated_count": len(to_update),
    }
