from collections import defaultdict

from django.db.models import Count, Max, Q, Sum
from django.db.models.functions import Coalesce

from analyst.models import Bulletin, Flow, FlowImport, IPReputation, Network, Structure
from analyst.models.choices import ReputationVerdict
from analyst.services.flows import apply_flow_filters

from .params import flow_filter_params_without_ordering, int_param, limit_param
from .tops import top_conversations, top_ports_protocols, top_talkers


def _filtered_flows(params):
    return apply_flow_filters(Flow.objects.all(), flow_filter_params_without_ordering(params)).order_by()


def _bulletins(params):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True)
    structure_id = int_param(params, "structure_id")
    if structure_id is not None:
        queryset = queryset.filter(structure_id=structure_id)
    return queryset


def _imports(params):
    queryset = FlowImport.objects.all()
    structure_id = int_param(params, "structure_id")
    if structure_id is not None:
        queryset = queryset.filter(structure_id=structure_id)
    network_id = int_param(params, "network_id")
    if network_id is not None:
        queryset = queryset.filter(
            Q(items__flow__network_id=network_id)
            | Q(items__flow__src_network_id=network_id)
            | Q(items__flow__dst_network_id=network_id)
        ).distinct()
    return queryset


def _count_map(queryset, field: str) -> dict:
    return {row[field]: row["count"] for row in queryset.values(field).annotate(count=Count("id")).order_by(field)}


def _latest_malicious_ips(flows, limit: int = 10) -> list[dict]:
    visible_ips = Q(ip_address__in=flows.values("src_ip")) | Q(ip_address__in=flows.values("dst_ip"))
    return [
        {
            "ip_address": item.ip_address,
            "country": item.country,
            "score": item.score,
            "source_count": item.source_count,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "last_analyzed_at": item.last_analyzed_at.isoformat() if item.last_analyzed_at else None,
        }
        for item in IPReputation.objects.filter(visible_ips, verdict=ReputationVerdict.MALICIOUS)
        .order_by("-last_seen_at", "-last_analyzed_at", "ip_address")[:limit]
    ]


def _malicious_communication_rankings(flows, limit: int = 10) -> dict:
    reputations = {
        item.ip_address: item
        for item in IPReputation.objects.filter(verdict=ReputationVerdict.MALICIOUS)
    }
    if not reputations:
        return {
            "ips_by_volume": [],
            "ips_by_duration": [],
            "hosts_by_volume": [],
            "hosts_by_duration": [],
            "pairs_by_volume": [],
        }

    malicious_ips = set(reputations)
    ip_rows = {}
    host_rows = {}
    pair_rows = defaultdict(
        lambda: {"flow_count": 0, "total_bytes": 0, "total_duration_seconds": 0}
    )
    relevant_flows = flows.filter(Q(src_ip__in=malicious_ips) | Q(dst_ip__in=malicious_ips))

    for flow in relevant_flows.iterator(chunk_size=1000):
        src_is_malicious = flow.src_ip in malicious_ips
        dst_is_malicious = flow.dst_ip in malicious_ips
        # Un classement hôte ↔ peer n'est fiable que si un seul côté est malveillant.
        if src_is_malicious == dst_is_malicious:
            continue
        malicious_peer = flow.src_ip if src_is_malicious else flow.dst_ip
        host_ip = flow.dst_ip if src_is_malicious else flow.src_ip
        total_bytes = flow.total_bytes or 0
        duration = flow.duration_seconds or 0

        reputation = reputations[malicious_peer]
        ip_row = ip_rows.setdefault(
            malicious_peer,
            {
                "ip_address": malicious_peer,
                "country": reputation.country,
                "score": reputation.score,
                "flow_count": 0,
                "total_bytes": 0,
                "total_duration_seconds": 0,
                "host_ips": set(),
                "last_seen_at": None,
            },
        )
        ip_row["flow_count"] += 1
        ip_row["total_bytes"] += total_bytes
        ip_row["total_duration_seconds"] += duration
        ip_row["host_ips"].add(host_ip)
        if ip_row["last_seen_at"] is None or flow.started_at > ip_row["last_seen_at"]:
            ip_row["last_seen_at"] = flow.started_at

        host_row = host_rows.setdefault(
            host_ip,
            {
                "host_ip": host_ip,
                "flow_count": 0,
                "total_bytes": 0,
                "total_duration_seconds": 0,
                "malicious_ips": set(),
                "last_seen_at": None,
            },
        )
        host_row["flow_count"] += 1
        host_row["total_bytes"] += total_bytes
        host_row["total_duration_seconds"] += duration
        host_row["malicious_ips"].add(malicious_peer)
        if host_row["last_seen_at"] is None or flow.started_at > host_row["last_seen_at"]:
            host_row["last_seen_at"] = flow.started_at

        pair_row = pair_rows[(host_ip, malicious_peer)]
        pair_row["flow_count"] += 1
        pair_row["total_bytes"] += total_bytes
        pair_row["total_duration_seconds"] += duration

    def ranked(rows, primary: str, secondary: str):
        return sorted(
            rows,
            key=lambda row: (row[primary], row[secondary], row["flow_count"]),
            reverse=True,
        )[:limit]

    def serialize_ip(row):
        return {
            **{key: value for key, value in row.items() if key != "host_ips"},
            "host_count": len(row["host_ips"]),
            "host_ips": sorted(row["host_ips"]),
            "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
        }

    def serialize_host(row):
        return {
            **{key: value for key, value in row.items() if key != "malicious_ips"},
            "malicious_peer_count": len(row["malicious_ips"]),
            "malicious_ips": sorted(row["malicious_ips"]),
            "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
        }

    ip_values = list(ip_rows.values())
    host_values = list(host_rows.values())
    pairs = [
        {"host_ip": host, "malicious_peer": peer, **values}
        for (host, peer), values in pair_rows.items()
    ]
    return {
        "ips_by_volume": [serialize_ip(row) for row in ranked(ip_values, "total_bytes", "total_duration_seconds")],
        "ips_by_duration": [serialize_ip(row) for row in ranked(ip_values, "total_duration_seconds", "total_bytes")],
        "hosts_by_volume": [serialize_host(row) for row in ranked(host_values, "total_bytes", "total_duration_seconds")],
        "hosts_by_duration": [serialize_host(row) for row in ranked(host_values, "total_duration_seconds", "total_bytes")],
        "pairs_by_volume": ranked(pairs, "total_bytes", "total_duration_seconds"),
    }


def build_dashboard_overview(params) -> dict:
    flows = _filtered_flows(params)
    flow_totals = flows.aggregate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
        latest_flow_at=Max("started_at"),
    )
    bulletins = _bulletins(params)
    imports = _imports(params)
    structure_id = int_param(params, "structure_id")
    structures = Structure.objects.filter(is_active=True)
    networks = Network.objects.filter(is_active=True)
    if structure_id is not None:
        structures = structures.filter(id=structure_id)
        networks = networks.filter(structure_id=structure_id)
    malicious_rankings = _malicious_communication_rankings(flows, limit=limit_param(params))

    return {
        "scope": {
            "structure_id": int_param(params, "structure_id"),
            "network_id": int_param(params, "network_id"),
            "started_from": params.get("started_from") or None,
            "started_to": params.get("started_to") or None,
        },
        "totals": {
            "structures": structures.count(),
            "networks": networks.count(),
            "flows": flow_totals["flow_count"],
            "total_bytes": flow_totals["total_bytes"],
            "total_packets": flow_totals["total_packets"],
            "imports": imports.count(),
            "bulletins": bulletins.count(),
            "latest_flow_at": flow_totals["latest_flow_at"].isoformat() if flow_totals["latest_flow_at"] else None,
        },
        "flows_by_direction": _count_map(flows, "direction"),
        "bulletins_by_status": _count_map(bulletins, "status"),
        "bulletins_by_severity": _count_map(bulletins, "severity"),
        "imports_by_status": _count_map(imports, "status"),
        "latest_malicious_ips": _latest_malicious_ips(flows),
        "top_malicious_ips_by_volume": malicious_rankings["ips_by_volume"],
        "top_malicious_ips_by_duration": malicious_rankings["ips_by_duration"],
        "top_hosts_with_malicious_by_volume": malicious_rankings["hosts_by_volume"],
        "top_hosts_with_malicious_by_duration": malicious_rankings["hosts_by_duration"],
        # Ancien contrat conservé pour les clients déjà déployés.
        "hosts_communicating_with_malicious": malicious_rankings["pairs_by_volume"],
        "top_talkers": top_talkers(params)["results"],
        "top_conversations": top_conversations(params)["results"],
        "top_ports_protocols": top_ports_protocols(params),
    }
