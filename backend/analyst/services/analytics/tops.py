from collections import defaultdict

from django.db import connection
from django.db.models import Count, Max, Min, Q, Sum
from django.db.models.functions import Coalesce

from analyst.models import Flow, IPReputation, PeerObservation
from analyst.models.choices import ReputationSource, ReputationStatus, ReputationVerdict
from analyst.services.flows import apply_flow_filters
from analyst.services.peer_observations import collect_peer_observation_stats

from .params import flow_filter_params_without_ordering, int_param, limit_param


def _filtered_flows(params):
    flows = apply_flow_filters(Flow.objects.all(), flow_filter_params_without_ordering(params)).order_by()
    peer_ips = [item for item in str(params.get("peer_ips") or "").replace(",", " ").split() if item]
    if peer_ips:
        flows = flows.filter(Q(src_ip__in=peer_ips) | Q(dst_ip__in=peer_ips))
    return flows


def top_talkers(params) -> dict:
    limit = limit_param(params)
    flows = _filtered_flows(params)
    rows = defaultdict(lambda: {
        "ip": "",
        "flow_count": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "first_seen": None,
        "last_seen": None,
        "as_source_count": 0,
        "as_destination_count": 0,
    })

    for item in flows.values("src_ip").annotate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
        first_seen=Min("started_at"),
        last_seen=Max("started_at"),
    ):
        row = rows[item["src_ip"]]
        row["ip"] = item["src_ip"]
        row["flow_count"] += item["flow_count"]
        row["total_bytes"] += item["total_bytes"]
        row["total_packets"] += item["total_packets"]
        row["as_source_count"] = item["flow_count"]
        row["first_seen"] = item["first_seen"] if row["first_seen"] is None or item["first_seen"] < row["first_seen"] else row["first_seen"]
        row["last_seen"] = item["last_seen"] if row["last_seen"] is None or item["last_seen"] > row["last_seen"] else row["last_seen"]

    for item in flows.values("dst_ip").annotate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
        first_seen=Min("started_at"),
        last_seen=Max("started_at"),
    ):
        row = rows[item["dst_ip"]]
        row["ip"] = item["dst_ip"]
        row["flow_count"] += item["flow_count"]
        row["total_bytes"] += item["total_bytes"]
        row["total_packets"] += item["total_packets"]
        row["as_destination_count"] = item["flow_count"]
        row["first_seen"] = item["first_seen"] if row["first_seen"] is None or item["first_seen"] < row["first_seen"] else row["first_seen"]
        row["last_seen"] = item["last_seen"] if row["last_seen"] is None or item["last_seen"] > row["last_seen"] else row["last_seen"]

    results = sorted(rows.values(), key=lambda row: (row["total_bytes"], row["flow_count"]), reverse=True)[:limit]
    for row in results:
        row["first_seen"] = row["first_seen"].isoformat() if row["first_seen"] else None
        row["last_seen"] = row["last_seen"].isoformat() if row["last_seen"] else None
    return {"limit": limit, "results": results}


def top_conversations(params) -> dict:
    limit = limit_param(params)
    rows = _filtered_flows(params).values("conversation_ip_a", "conversation_ip_b").annotate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
        first_seen=Min("started_at"),
        last_seen=Max("started_at"),
    ).order_by("-total_bytes", "-flow_count")[:limit]

    return {
        "limit": limit,
        "results": [
            {
                "conversation_ip_a": row["conversation_ip_a"],
                "conversation_ip_b": row["conversation_ip_b"],
                "flow_count": row["flow_count"],
                "total_bytes": row["total_bytes"],
                "total_packets": row["total_packets"],
                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            }
            for row in rows
        ],
    }


def top_ports_protocols(params) -> dict:
    limit = limit_param(params)
    flows = _filtered_flows(params)
    ports = flows.values("dst_port", "protocol", "service").annotate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
    ).order_by("-total_bytes", "-flow_count")[:limit]
    protocols = flows.values("protocol").annotate(
        flow_count=Count("id"),
        total_bytes=Coalesce(Sum("total_bytes"), 0),
        total_packets=Coalesce(Sum("total_packets"), 0),
    ).order_by("-total_bytes", "-flow_count")[:limit]

    return {
        "limit": limit,
        "ports": [
            {
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "service": row["service"],
                "flow_count": row["flow_count"],
                "total_bytes": row["total_bytes"],
                "total_packets": row["total_packets"],
            }
            for row in ports
        ],
        "protocols": [
            {
                "protocol": row["protocol"],
                "flow_count": row["flow_count"],
                "total_bytes": row["total_bytes"],
                "total_packets": row["total_packets"],
            }
            for row in protocols
        ],
    }


def top_peers(params) -> dict:
    limit = limit_param(params)
    stats = collect_peer_observation_stats(_filtered_flows(params))
    imported_countries = {}
    for key, item in stats.items():
        peer_ip = key[1]
        if item.get("peer_country") and not imported_countries.get(peer_ip):
            imported_countries[peer_ip] = item["peer_country"]
    reputations = {}
    peer_ips = list({key[1] for key in stats.keys()})
    max_query_params = connection.features.max_query_params
    chunk_size = 10_000 if max_query_params is None else max(max_query_params - 10, 1)
    for offset in range(0, len(peer_ips), chunk_size):
        for item in IPReputation.objects.filter(
            ip_address__in=peer_ips[offset:offset + chunk_size]
        ).prefetch_related("results"):
            reputations[item.ip_address] = item
    rows = defaultdict(
        lambda: {
            "peer_ip": "",
            "country": "",
            "verdict": "unknown",
            "score": None,
            "source_count": 0,
            "successful_source_count": 0,
            "reputation_results": [],
            "flow_count": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "total_duration_seconds": 0,
            "max_duration_seconds": None,
            "avg_duration_seconds": None,
            "first_seen": None,
            "last_seen": None,
            "host_count": 0,
            "host_ips": set(),
            "host_ports": set(),
            "services": set(),
            "protocols": set(),
            "networks": {},
        }
    )
    host_port_filter = int_param(params, "host_port")
    host_service_filter = params.get("host_service") or params.get("service")

    for (
        network_id,
        peer_ip,
        host_ip,
        host_port,
        host_service,
        _host_port_category,
    ), item in stats.items():
        if host_port_filter is not None and host_port != host_port_filter:
            continue
        if host_service_filter and host_service_filter.lower() not in host_service.lower():
            continue
        reputation = reputations.get(peer_ip)
        row = rows[peer_ip]
        row["peer_ip"] = peer_ip
        if reputation:
            successful_results = {
                result.source: result
                for result in reputation.results.all()
                if result.status == ReputationStatus.SUCCESS and result.country
            }
            platform_country = next((
                successful_results[source].country
                for source in (ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL)
                if source in successful_results
            ), "")
            row["country"] = platform_country or reputation.country or imported_countries.get(peer_ip) or row["country"]
            row["verdict"] = reputation.verdict
            row["score"] = reputation.score
            row["source_count"] = reputation.source_count
            row["successful_source_count"] = reputation.successful_source_count
            row["reputation_results"] = [
                {
                    "source": result.source,
                    "status": result.status,
                    "verdict": result.verdict,
                    "score": result.score,
                    "country": result.country,
                    "analyzed_at": result.analyzed_at.isoformat() if result.analyzed_at else None,
                }
                for result in reputation.results.all()
            ]
        elif imported_countries.get(peer_ip):
            row["country"] = imported_countries[peer_ip]
        row["flow_count"] += item["flow_count"]
        row["total_bytes"] += item["total_bytes"]
        row["total_packets"] += item["total_packets"]
        row["total_duration_seconds"] += item["total_duration_seconds"]
        row["max_duration_seconds"] = (
            item["max_duration_seconds"]
            if row["max_duration_seconds"] is None
            or (item["max_duration_seconds"] is not None and item["max_duration_seconds"] > row["max_duration_seconds"])
            else row["max_duration_seconds"]
        )
        row["first_seen"] = (
            item["first_seen_at"]
            if row["first_seen"] is None or item["first_seen_at"] < row["first_seen"]
            else row["first_seen"]
        )
        row["last_seen"] = (
            item["last_seen_at"]
            if row["last_seen"] is None or item["last_seen_at"] > row["last_seen"]
            else row["last_seen"]
        )
        if host_ip:
            row["host_ips"].add(host_ip)
        if host_port is not None:
            row["host_ports"].add(host_port)
        if host_service:
            row["services"].add(host_service)
        row["protocols"].update(item.get("protocols", set()))
        row["networks"][network_id] = row["networks"].get(network_id, 0) + item["flow_count"]

    verdict = params.get("verdict") or params.get("peer_verdict")
    malicious_only = str(params.get("malicious_only", "")).lower() in {"1", "true", "yes"}
    suspicious_only = str(params.get("suspicious_only", "")).lower() in {"1", "true", "yes"}
    country = params.get("country")
    min_total_bytes = int_param(params, "min_total_bytes")
    min_duration = int_param(params, "min_total_duration_seconds")
    if min_duration is None:
        min_duration = int_param(params, "min_duration_seconds")
    if min_duration is None:
        min_duration = int_param(params, "min_duration")
    min_flow_count = int_param(params, "min_flow_count")

    def keep(row):
        if malicious_only and row["verdict"] != ReputationVerdict.MALICIOUS:
            return False
        if suspicious_only and row["verdict"] not in (ReputationVerdict.MALICIOUS, ReputationVerdict.SUSPICIOUS):
            return False
        if verdict and row["verdict"] != verdict:
            return False
        if country and row["country"].lower() != country.lower():
            return False
        if min_total_bytes is not None and row["total_bytes"] < min_total_bytes:
            return False
        if min_duration is not None and row["total_duration_seconds"] < min_duration:
            return False
        if min_flow_count is not None and row["flow_count"] < min_flow_count:
            return False
        return True

    results = [row for row in rows.values() if keep(row)]
    sort = params.get("sort") or "verdict"
    verdict_rank = {
        ReputationVerdict.MALICIOUS: 3,
        ReputationVerdict.SUSPICIOUS: 2,
        ReputationVerdict.UNKNOWN: 1,
        ReputationVerdict.CLEAN: 0,
    }
    sort_key = {
        "verdict": lambda row: (
            verdict_rank.get(row["verdict"], 1),
            row["score"] if row["score"] is not None else -1,
            row["total_duration_seconds"],
            row["total_bytes"],
        ),
        "total_duration_seconds": lambda row: (row["total_duration_seconds"], row["total_bytes"], row["flow_count"]),
        "total_bytes": lambda row: (row["total_bytes"], row["total_duration_seconds"], row["flow_count"]),
        "flow_count": lambda row: (row["flow_count"], row["total_duration_seconds"], row["total_bytes"]),
        "score": lambda row: (row["score"] or -1, row["total_duration_seconds"], row["flow_count"]),
        "last_seen_at": lambda row: (row["last_seen"], row["total_duration_seconds"], row["flow_count"]),
    }.get(sort, lambda row: (row["total_duration_seconds"], row["total_bytes"], row["flow_count"]))
    results = sorted(results, key=sort_key, reverse=True)[:limit]

    observations_by_peer = defaultdict(list)
    include_observations = str(params.get("include_observations", "true")).lower() not in {"0", "false", "no"}
    if include_observations:
        result_peer_ips = [row["peer_ip"] for row in results]
        observations = PeerObservation.objects.select_related(
            "peer_reputation", "network", "network__structure"
        ).filter(peer_reputation__ip_address__in=result_peer_ips)
        structure_id = int_param(params, "structure_id")
        if structure_id is not None:
            observations = observations.filter(network__structure_id=structure_id)
        if host_port_filter is not None:
            observations = observations.filter(host_port=host_port_filter)
        if host_service_filter:
            observations = observations.filter(host_service__icontains=host_service_filter)
        for observation in observations:
            observations_by_peer[observation.peer_ip].append({
                "id": observation.id,
                "network": observation.network_id,
                "structure_id": observation.network.structure_id,
                "structure_code": observation.network.structure.code,
                "host_ip": observation.host_ip,
                "host_port": observation.host_port,
                "host_service": observation.host_service,
                "host_port_category": observation.host_port_category,
                "flow_count": observation.flow_count,
                "total_bytes": observation.total_bytes,
                "total_packets": observation.total_packets,
                "total_duration_seconds": observation.total_duration_seconds,
                "first_seen_at": observation.first_seen_at.isoformat() if observation.first_seen_at else None,
                "last_seen_at": observation.last_seen_at.isoformat() if observation.last_seen_at else None,
            })

    for row in results:
        row["host_count"] = len(row["host_ips"])
        row["avg_duration_seconds"] = row["total_duration_seconds"] / row["flow_count"] if row["flow_count"] else None
        row["first_seen"] = row["first_seen"].isoformat() if row["first_seen"] else None
        row["last_seen"] = row["last_seen"].isoformat() if row["last_seen"] else None
        row["host_ips"] = sorted(row["host_ips"])
        row["host_ports"] = sorted(row["host_ports"])
        row["services"] = sorted(row["services"])
        row["protocols"] = sorted(row["protocols"])
        row["networks"] = [
            {"network_id": network_id, "flow_count": flow_count}
            for network_id, flow_count in sorted(row["networks"].items())
        ]
        row["observations"] = observations_by_peer[row["peer_ip"]]
        row["observation_ids"] = [item["id"] for item in row["observations"]]
    return {"limit": limit, "sort": sort, "results": results}
