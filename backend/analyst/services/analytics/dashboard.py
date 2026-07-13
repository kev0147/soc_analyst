from collections import Counter

from django.db.models import Count, Max, Q, Sum
from django.db.models.functions import Coalesce

from analyst.models import Bulletin, Flow, FlowImport, IPReputation, Network, Structure
from analyst.models.choices import ReputationVerdict
from analyst.services.flows import apply_flow_filters

from .params import flow_filter_params_without_ordering, int_param
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
        queryset = queryset.filter(network__structure_id=structure_id)
    network_id = int_param(params, "network_id")
    if network_id is not None:
        queryset = queryset.filter(network_id=network_id)
    return queryset


def _count_map(queryset, field: str) -> dict:
    return {row[field]: row["count"] for row in queryset.values(field).annotate(count=Count("id")).order_by(field)}


def _latest_malicious_ips(limit: int = 10) -> list[dict]:
    return [
        {
            "ip_address": item.ip_address,
            "country": item.country,
            "score": item.score,
            "source_count": item.source_count,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "last_analyzed_at": item.last_analyzed_at.isoformat() if item.last_analyzed_at else None,
        }
        for item in IPReputation.objects.filter(verdict=ReputationVerdict.MALICIOUS)
        .order_by("-last_seen_at", "-last_analyzed_at", "ip_address")[:limit]
    ]


def _hosts_communicating_with_malicious(flows, limit: int = 10) -> list[dict]:
    malicious_ips = set(
        IPReputation.objects.filter(verdict=ReputationVerdict.MALICIOUS).values_list("ip_address", flat=True)
    )
    if not malicious_ips:
        return []
    counters = Counter()
    bytes_counter = Counter()
    for flow in flows.filter(Q(src_ip__in=malicious_ips) | Q(dst_ip__in=malicious_ips)).iterator(chunk_size=1000):
        if flow.src_ip in malicious_ips:
            host = flow.dst_ip
            malicious_peer = flow.src_ip
        else:
            host = flow.src_ip
            malicious_peer = flow.dst_ip
        key = (host, malicious_peer)
        counters[key] += 1
        bytes_counter[key] += flow.total_bytes or 0
    return [
        {
            "host_ip": host,
            "malicious_peer": malicious_peer,
            "flow_count": counters[(host, malicious_peer)],
            "total_bytes": bytes_counter[(host, malicious_peer)],
        }
        for host, malicious_peer in sorted(counters, key=lambda key: (bytes_counter[key], counters[key]), reverse=True)[:limit]
    ]


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

    return {
        "scope": {
            "structure_id": int_param(params, "structure_id"),
            "network_id": int_param(params, "network_id"),
            "started_from": params.get("started_from") or None,
            "started_to": params.get("started_to") or None,
        },
        "totals": {
            "structures": Structure.objects.filter(is_active=True).count(),
            "networks": Network.objects.filter(is_active=True).count(),
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
        "latest_malicious_ips": _latest_malicious_ips(),
        "hosts_communicating_with_malicious": _hosts_communicating_with_malicious(flows),
        "top_talkers": top_talkers(params)["results"],
        "top_conversations": top_conversations(params)["results"],
        "top_ports_protocols": top_ports_protocols(params),
    }
