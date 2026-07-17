import hashlib
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone as datetime_timezone

from django.db import transaction

from analyst.models import DailyFlowAggregate, Flow, IPReputation, Structure
from analyst.models.choices import ReputationVerdict
from analyst.services.imports.flow_mapper import internal_cidrs_for_structure
from analyst.services.peer_observations import _observation_endpoint


def _parse_date(value, name: str) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} doit être une date ISO valide.") from exc


def _dedupe_key(day, structure_id, network_id, host_ip, peer_ip, host_port, protocol, service, direction):
    raw = "|".join(str(item if item not in (None, "") else "-") for item in (
        day,
        structure_id,
        network_id,
        host_ip,
        peer_ip,
        host_port,
        protocol,
        service,
        direction,
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_bucket():
    return {
        "flow_count": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "total_duration_seconds": 0,
        "max_duration_seconds": None,
        "first_seen_at": None,
        "last_seen_at": None,
        "peer_ports": set(),
        "peer_country": "",
        "reputation_verdict": ReputationVerdict.UNKNOWN,
        "reputation_score": None,
    }


def build_daily_flow_aggregates(*, date_from, date_to, structure_id=None, progress_callback=None) -> dict:
    start_date = _parse_date(date_from, "date_from")
    end_date = _parse_date(date_to, "date_to")
    if end_date < start_date:
        raise ValueError("date_to doit être postérieure ou égale à date_from.")
    day_count = (end_date - start_date).days + 1
    if day_count > 366:
        raise ValueError("Une agrégation est limitée à 366 jours par exécution.")
    if structure_id and not Structure.objects.filter(pk=structure_id).exists():
        raise ValueError("Structure introuvable.")

    reputations = {item.ip_address: item for item in IPReputation.objects.all()}
    cidr_cache = {}
    total_flows = 0
    total_rows = 0

    for offset in range(day_count):
        day = start_date + timedelta(days=offset)
        started_at = datetime.combine(day, time.min, tzinfo=datetime_timezone.utc)
        ended_at = started_at + timedelta(days=1)
        flows = Flow.objects.select_related("network", "network__structure").filter(
            started_at__gte=started_at,
            started_at__lt=ended_at,
        )
        if structure_id:
            flows = flows.filter(network__structure_id=structure_id)

        buckets = defaultdict(_new_bucket)
        day_flow_count = 0
        for flow in flows.iterator(chunk_size=1000):
            day_flow_count += 1
            current_structure_id = flow.network.structure_id
            if current_structure_id not in cidr_cache:
                cidr_cache[current_structure_id] = internal_cidrs_for_structure(flow.network.structure)
            endpoint = _observation_endpoint(flow, cidr_cache[current_structure_id])
            if endpoint is None:
                continue
            peer_is_source = endpoint.peer_ip == flow.src_ip
            peer_port = flow.src_port if peer_is_source else flow.dst_port
            peer_country = flow.src_location if peer_is_source else flow.dst_location
            reputation = reputations.get(endpoint.peer_ip)
            key = (
                current_structure_id,
                flow.network_id,
                endpoint.host_ip,
                endpoint.peer_ip,
                endpoint.host_port,
                flow.protocol or "",
                endpoint.host_service,
                flow.direction,
            )
            bucket = buckets[key]
            duration = flow.duration_seconds or 0
            bucket["flow_count"] += 1
            bucket["total_bytes"] += flow.total_bytes or 0
            bucket["total_packets"] += flow.total_packets or 0
            bucket["total_duration_seconds"] += duration
            bucket["max_duration_seconds"] = (
                duration
                if bucket["max_duration_seconds"] is None or duration > bucket["max_duration_seconds"]
                else bucket["max_duration_seconds"]
            )
            bucket["first_seen_at"] = (
                flow.started_at
                if bucket["first_seen_at"] is None or flow.started_at < bucket["first_seen_at"]
                else bucket["first_seen_at"]
            )
            bucket["last_seen_at"] = (
                flow.started_at
                if bucket["last_seen_at"] is None or flow.started_at > bucket["last_seen_at"]
                else bucket["last_seen_at"]
            )
            if peer_port is not None:
                bucket["peer_ports"].add(peer_port)
            bucket["peer_country"] = (reputation.country if reputation else "") or peer_country or bucket["peer_country"]
            if reputation:
                bucket["reputation_verdict"] = reputation.verdict
                bucket["reputation_score"] = reputation.score

        aggregates = []
        for key, bucket in buckets.items():
            (
                current_structure_id,
                network_id,
                host_ip,
                peer_ip,
                host_port,
                protocol,
                service,
                direction,
            ) = key
            aggregates.append(DailyFlowAggregate(
                date=day,
                structure_id=current_structure_id,
                network_id=network_id,
                dedupe_key=_dedupe_key(
                    day,
                    current_structure_id,
                    network_id,
                    host_ip,
                    peer_ip,
                    host_port,
                    protocol,
                    service,
                    direction,
                ),
                host_ip=host_ip,
                peer_ip=peer_ip,
                host_port=host_port,
                peer_port=next(iter(bucket["peer_ports"])) if len(bucket["peer_ports"]) == 1 else None,
                protocol=protocol,
                service=service,
                direction=direction,
                peer_country=bucket["peer_country"],
                reputation_verdict=bucket["reputation_verdict"],
                reputation_score=bucket["reputation_score"],
                flow_count=bucket["flow_count"],
                total_bytes=bucket["total_bytes"],
                total_packets=bucket["total_packets"],
                total_duration_seconds=bucket["total_duration_seconds"],
                max_duration_seconds=bucket["max_duration_seconds"],
                first_seen_at=bucket["first_seen_at"],
                last_seen_at=bucket["last_seen_at"],
            ))

        with transaction.atomic():
            existing = DailyFlowAggregate.objects.filter(date=day)
            if structure_id:
                existing = existing.filter(structure_id=structure_id)
            existing.delete()
            DailyFlowAggregate.objects.bulk_create(aggregates, batch_size=500)

        total_flows += day_flow_count
        total_rows += len(aggregates)
        if progress_callback:
            progress_callback(offset + 1, day_count, f"Agrégation du {day.isoformat()}")

    return {
        "date_from": start_date.isoformat(),
        "date_to": end_date.isoformat(),
        "structure_id": structure_id,
        "day_count": day_count,
        "flow_count": total_flows,
        "aggregate_count": total_rows,
        "flows_deleted": 0,
    }
