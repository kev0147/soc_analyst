import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import connection
from django.utils import timezone

from analyst.models import Flow, FlowImport, IPReputation, IPReputationResult
from analyst.models.choices import ReputationSource, ReputationStatus
from analyst.services.imports.flow_mapper import internal_cidrs_for_structure
from analyst.services.peer_observations import sync_peer_observations

from .clients import CLIENTS, ReputationClientResult
from .verdicts import aggregate_verdict


DEFAULT_LIMIT = 50
MAX_LIMIT = 500
REPUTATION_TOOLS = (ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL)
PRIORITY_RANK = {"never_analyzed": 0, "missing": 1, "expired": 2, "forced": 3}


@dataclass(frozen=True)
class CandidateIP:
    ip_address: str
    flow_count: int
    first_seen_at: object
    last_seen_at: object
    analyzed_source_count: int
    missing_tools: tuple[str, ...]
    expired_tools: tuple[str, ...]
    fresh_tools: tuple[str, ...]
    due_tools: tuple[str, ...]
    priority: str


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


def candidate_ips(
    scope: str = "all_flows",
    import_id: int | None = None,
    limit: int = DEFAULT_LIMIT,
    tools: list[str] | None = None,
    force_refresh: bool = False,
) -> list[CandidateIP]:
    limit = min(max(int(limit or DEFAULT_LIMIT), 1), MAX_LIMIT)
    selected_tools = _enabled_tools(tools)
    stats = _external_ip_stats(_flow_queryset(scope, import_id))
    results_by_ip = defaultdict(dict)
    ip_addresses = list(stats)
    max_query_params = connection.features.max_query_params
    chunk_size = 10_000 if max_query_params is None else max(max_query_params - len(selected_tools) - 10, 1)
    for offset in range(0, len(ip_addresses), chunk_size):
        chunk = ip_addresses[offset:offset + chunk_size]
        for result in IPReputationResult.objects.filter(
            reputation__ip_address__in=chunk,
            source__in=selected_tools,
        ).select_related("reputation"):
            results_by_ip[result.reputation.ip_address][result.source] = result

    candidates = []
    for ip, row in stats.items():
        current_results = results_by_ip[ip]
        missing_tools = tuple(tool for tool in selected_tools if tool not in current_results)
        expired_tools = tuple(
            tool for tool in selected_tools if tool in current_results and current_results[tool].is_stale
        )
        fresh_tools = tuple(
            tool for tool in selected_tools if tool in current_results and not current_results[tool].is_stale
        )
        due_tools = tuple(selected_tools) if force_refresh else missing_tools + expired_tools
        if not due_tools:
            continue
        if len(missing_tools) == len(selected_tools):
            priority = "never_analyzed"
        elif missing_tools:
            priority = "missing"
        elif expired_tools:
            priority = "expired"
        else:
            priority = "forced"
        candidates.append(CandidateIP(
            ip_address=ip,
            flow_count=row["flow_count"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            analyzed_source_count=len(current_results),
            missing_tools=missing_tools,
            expired_tools=expired_tools,
            fresh_tools=fresh_tools,
            due_tools=due_tools,
            priority=priority,
        ))
    return sorted(
        candidates,
        key=lambda item: (PRIORITY_RANK[item.priority], -item.flow_count, item.ip_address),
    )[:limit]


def _enabled_tools(tools: list[str] | None) -> list[str]:
    if not tools:
        return list(REPUTATION_TOOLS)
    valid = set(REPUTATION_TOOLS)
    selected = list(dict.fromkeys(tool for tool in tools if tool in valid))
    if not selected:
        raise ValueError("Aucun outil de réputation valide. Utilisez abuseipdb et/ou virustotal.")
    return selected


def _result_expiry(result: ReputationClientResult):
    if result.status != ReputationStatus.SUCCESS:
        hours = settings.IP_REPUTATION_ERROR_RETRY_HOURS
    elif result.source == ReputationSource.ABUSEIPDB:
        hours = settings.IP_REPUTATION_ABUSEIPDB_TTL_HOURS
    else:
        hours = settings.IP_REPUTATION_VIRUSTOTAL_TTL_HOURS
    return result.analyzed_at + timedelta(hours=hours)


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
            "expires_at": _result_expiry(result),
        },
    )


def _refresh_reputation(reputation: IPReputation, candidate: CandidateIP):
    results = list(reputation.results.filter(source__in=REPUTATION_TOOLS))
    successful = [result for result in results if result.status == ReputationStatus.SUCCESS]
    reputation.source_count = len(results)
    reputation.successful_source_count = len(successful)
    reputation.verdict = aggregate_verdict(results)
    reputation.score = max((result.score for result in successful if result.score is not None), default=None)
    reputation.country = next((result.country for result in successful if result.country), reputation.country)
    reputation.flow_count = candidate.flow_count
    reputation.first_seen_at = candidate.first_seen_at
    reputation.last_seen_at = candidate.last_seen_at
    reputation.last_analyzed_at = max((result.analyzed_at for result in results), default=timezone.now())
    reputation.save()


def run_reputation_analysis(
    scope: str = "all_flows",
    import_id: int | None = None,
    tools: list[str] | None = None,
    limit: int = DEFAULT_LIMIT,
    client_classes=None,
    progress_callback=None,
    force_refresh: bool = False,
) -> dict:
    selected_tools = _enabled_tools(tools)
    candidates = candidate_ips(
        scope=scope,
        import_id=import_id,
        limit=limit,
        tools=selected_tools,
        force_refresh=force_refresh,
    )
    clients = client_classes or CLIENTS
    analyzed = []
    source_analysis_count = 0

    if progress_callback:
        progress_callback(0, len(candidates), "Préparation des candidats")

    for index, candidate in enumerate(candidates, start=1):
        reputation, _ = IPReputation.objects.get_or_create(ip_address=candidate.ip_address)
        for tool in candidate.due_tools:
            client = clients[tool]()
            result = client.analyze(candidate.ip_address)
            _upsert_result(reputation, result)
            source_analysis_count += 1
        _refresh_reputation(reputation, candidate)
        analyzed.append((reputation, candidate.due_tools))
        if progress_callback:
            progress_callback(index, len(candidates), f"Analyse de {candidate.ip_address}")

    if progress_callback:
        progress_callback(len(candidates), len(candidates), "Synchronisation des observations")
    observation_sync = sync_peer_observations(
        scope="all_flows",
        progress_callback=progress_callback,
    )

    return {
        "scope": scope,
        "import_id": import_id,
        "tools": selected_tools,
        "force_refresh": force_refresh,
        "candidate_count": len(candidates),
        "analyzed_count": len(analyzed),
        "source_analysis_count": source_analysis_count,
        "observation_sync": observation_sync,
        "records": [
            {
                "ip_address": item.ip_address,
                "verdict": item.verdict,
                "score": item.score,
                "country": item.country,
                "source_count": item.source_count,
                "successful_source_count": item.successful_source_count,
                "refreshed_tools": list(refreshed_tools),
            }
            for item, refreshed_tools in analyzed
        ],
    }
