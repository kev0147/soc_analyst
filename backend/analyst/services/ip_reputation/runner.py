import ipaddress
from collections import defaultdict
from dataclasses import dataclass

from django.db.models import Count, Q
from django.utils import timezone

from analyst.models import Flow, FlowImport, IPReputation, IPReputationResult
from analyst.models.choices import ReputationSource, ReputationStatus
from analyst.services.imports.flow_mapper import internal_cidrs_for_structure
from analyst.services.peer_observations import sync_peer_observations

from .clients import CLIENTS, ReputationClientResult
from .verdicts import aggregate_verdict


DEFAULT_LIMIT = 50
MAX_LIMIT = 500


@dataclass(frozen=True)
class CandidateIP:
    ip_address: str
    flow_count: int
    first_seen_at: object
    last_seen_at: object
    analyzed_source_count: int


def _flow_queryset(scope: str, import_id: int | None = None):
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


def _external_ip_stats(flows) -> dict[str, dict]:
    stats = defaultdict(lambda: {"flow_count": 0, "first_seen_at": None, "last_seen_at": None})
    cidr_cache = {}
    for flow in flows.iterator(chunk_size=1000):
        structure_id = flow.network.structure_id
        if structure_id not in cidr_cache:
            cidr_cache[structure_id] = internal_cidrs_for_structure(flow.network.structure)
        cidrs = cidr_cache[structure_id]
        for ip in (flow.src_ip, flow.dst_ip):
            if _is_internal(ip, cidrs):
                continue
            row = stats[ip]
            row["flow_count"] += 1
            row["first_seen_at"] = flow.started_at if row["first_seen_at"] is None or flow.started_at < row["first_seen_at"] else row["first_seen_at"]
            row["last_seen_at"] = flow.started_at if row["last_seen_at"] is None or flow.started_at > row["last_seen_at"] else row["last_seen_at"]
    return stats


def candidate_ips(scope: str = "all_flows", import_id: int | None = None, limit: int = DEFAULT_LIMIT) -> list[CandidateIP]:
    limit = min(max(int(limit or DEFAULT_LIMIT), 1), MAX_LIMIT)
    stats = _external_ip_stats(_flow_queryset(scope, import_id))
    existing_counts = dict(
        IPReputation.objects.filter(ip_address__in=stats.keys()).values_list("ip_address", "source_count")
    )
    candidates = [
        CandidateIP(
            ip_address=ip,
            flow_count=row["flow_count"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            analyzed_source_count=existing_counts.get(ip, 0),
        )
        for ip, row in stats.items()
    ]
    return sorted(candidates, key=lambda item: (item.analyzed_source_count, -item.flow_count, item.ip_address))[:limit]


def _enabled_tools(tools: list[str] | None) -> list[str]:
    if not tools:
        return [ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL, ReputationSource.SHODAN]
    valid = set(ReputationSource.values)
    selected = [tool for tool in tools if tool in valid]
    if not selected:
        raise ValueError("Aucun outil d'analyse valide.")
    return selected


def _upsert_result(reputation: IPReputation, result: ReputationClientResult):
    IPReputationResult.objects.update_or_create(
        reputation=reputation,
        source=result.source,
        defaults={
            "status": result.status,
            "verdict": result.verdict,
            "score": result.score,
            "country": result.country,
            "raw": result.raw,
            "error_message": result.error_message,
            "analyzed_at": result.analyzed_at,
        },
    )


def _refresh_reputation(reputation: IPReputation, candidate: CandidateIP):
    results = list(reputation.results.all())
    successful = [result for result in results if result.status == ReputationStatus.SUCCESS]
    reputation.source_count = len(results)
    reputation.successful_source_count = len(successful)
    reputation.verdict = aggregate_verdict(results)
    reputation.score = max((result.score for result in successful if result.score is not None), default=None)
    reputation.country = next((result.country for result in successful if result.country), reputation.country)
    reputation.flow_count = candidate.flow_count
    reputation.first_seen_at = candidate.first_seen_at
    reputation.last_seen_at = candidate.last_seen_at
    reputation.last_analyzed_at = timezone.now()
    reputation.save()


def run_reputation_analysis(
    scope: str = "all_flows",
    import_id: int | None = None,
    tools: list[str] | None = None,
    limit: int = DEFAULT_LIMIT,
    client_classes=None,
    progress_callback=None,
) -> dict:
    selected_tools = _enabled_tools(tools)
    candidates = candidate_ips(scope=scope, import_id=import_id, limit=limit)
    clients = client_classes or CLIENTS
    analyzed = []

    if progress_callback:
        progress_callback(0, len(candidates), "Préparation des candidats")

    for index, candidate in enumerate(candidates, start=1):
        reputation, _ = IPReputation.objects.get_or_create(ip_address=candidate.ip_address)
        for tool in selected_tools:
            if reputation.results.filter(source=tool, status=ReputationStatus.SUCCESS).exists():
                continue
            client = clients[tool]()
            result = client.analyze(candidate.ip_address)
            _upsert_result(reputation, result)
        _refresh_reputation(reputation, candidate)
        analyzed.append(reputation)
        if progress_callback:
            progress_callback(index, len(candidates), f"Analyse de {candidate.ip_address}")

    if progress_callback:
        progress_callback(len(candidates), len(candidates), "Synchronisation des observations")
    observation_sync = sync_peer_observations(scope=scope, import_id=import_id)

    return {
        "scope": scope,
        "import_id": import_id,
        "tools": selected_tools,
        "candidate_count": len(candidates),
        "analyzed_count": len(analyzed),
        "observation_sync": observation_sync,
        "records": [
            {
                "ip_address": item.ip_address,
                "verdict": item.verdict,
                "score": item.score,
                "country": item.country,
                "source_count": item.source_count,
                "successful_source_count": item.successful_source_count,
            }
            for item in analyzed
        ],
    }
