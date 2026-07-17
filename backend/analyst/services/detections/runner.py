import hashlib
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

from analyst.models import DetectionHit, DetectionRule, Flow, FlowImport, IPReputation, Structure
from analyst.models.choices import DetectionRuleType, ReputationVerdict
from analyst.services.flows import apply_flow_filters
from analyst.services.imports.flow_mapper import internal_cidrs_for_structure
from analyst.services.peer_observations import _observation_endpoint


def _scoped_flows(payload: dict):
    scope = payload.get("scope") or "all_flows"
    params = {}
    if scope == "structure":
        structure_id = payload.get("structure_id")
        if not structure_id or not Structure.objects.filter(pk=structure_id).exists():
            raise ValueError("Une structure valide est obligatoire pour ce périmètre.")
        params["structure_id"] = structure_id
    elif scope == "import":
        import_id = payload.get("import_id")
        if not import_id or not FlowImport.objects.filter(pk=import_id).exists():
            raise ValueError("Un import valide est obligatoire pour ce périmètre.")
        params["import_id"] = import_id
    elif scope == "date_range":
        if not payload.get("date_from") or not payload.get("date_to"):
            raise ValueError("Les dates de début et de fin sont obligatoires.")
        params["date_from"] = payload["date_from"]
        params["date_to"] = payload["date_to"]
        if payload.get("structure_id"):
            params["structure_id"] = payload["structure_id"]
    elif scope != "all_flows":
        raise ValueError("Périmètre de détection inconnu.")
    return apply_flow_filters(Flow.objects.all(), params).order_by()


def _new_bucket():
    return {
        "flow_count": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "total_duration_seconds": 0,
        "max_duration_seconds": 0,
        "first_seen_at": None,
        "last_seen_at": None,
        "host_ips": set(),
        "host_ports": set(),
        "peer_ports": set(),
        "services": set(),
        "network_ids": set(),
        "sample_flow_ids": [],
        "sample_sna_flow_ids": [],
        "peer_country": "",
        "reputation_verdict": ReputationVerdict.UNKNOWN,
        "reputation_score": None,
    }


def _add_flow(bucket, flow, endpoint, peer_port, reputation, peer_country):
    duration = flow.duration_seconds or 0
    bucket["flow_count"] += 1
    bucket["total_bytes"] += flow.total_bytes or 0
    bucket["total_packets"] += flow.total_packets or 0
    bucket["total_duration_seconds"] += duration
    bucket["max_duration_seconds"] = max(bucket["max_duration_seconds"], duration)
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
    bucket["host_ips"].add(endpoint.host_ip)
    if endpoint.host_port is not None:
        bucket["host_ports"].add(endpoint.host_port)
    if peer_port is not None:
        bucket["peer_ports"].add(peer_port)
    if endpoint.host_service:
        bucket["services"].add(endpoint.host_service)
    bucket["network_ids"].add(flow.network_id)
    if len(bucket["sample_flow_ids"]) < 20:
        bucket["sample_flow_ids"].append(flow.id)
        bucket["sample_sna_flow_ids"].append(flow.sna_flow_id)
    bucket["peer_country"] = (reputation.country if reputation else "") or peer_country or bucket["peer_country"]
    if reputation:
        bucket["reputation_verdict"] = reputation.verdict
        bucket["reputation_score"] = reputation.score


def _dedupe_key(rule, date, structure_id, entity_parts):
    raw = "|".join([rule.code, date.isoformat(), str(structure_id), *[str(item or "-") for item in entity_parts]])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _candidate(rule, date, structure_id, entity_parts, bucket, *, host_ip=None, peer_ip=None, host_port=None):
    network_ids = sorted(bucket["network_ids"])
    return {
        "rule": rule,
        "structure_id": structure_id,
        "network_id": network_ids[0] if len(network_ids) == 1 else None,
        "dedupe_key": _dedupe_key(rule, date, structure_id, entity_parts),
        "severity": rule.severity,
        "observation_date": date,
        "host_ip": host_ip,
        "peer_ip": peer_ip,
        "host_port": host_port,
        "peer_port": next(iter(bucket["peer_ports"])) if len(bucket["peer_ports"]) == 1 else None,
        "service": next(iter(bucket["services"])) if len(bucket["services"]) == 1 else "",
        "peer_country": bucket["peer_country"],
        "reputation_verdict": bucket["reputation_verdict"],
        "reputation_score": bucket["reputation_score"],
        "flow_count": bucket["flow_count"],
        "host_count": len(bucket["host_ips"]),
        "total_bytes": bucket["total_bytes"],
        "total_packets": bucket["total_packets"],
        "total_duration_seconds": bucket["total_duration_seconds"],
        "first_seen_at": bucket["first_seen_at"],
        "last_seen_at": bucket["last_seen_at"],
        "evidence": {
            "host_ips": sorted(bucket["host_ips"]),
            "host_ports": sorted(bucket["host_ports"]),
            "peer_ports": sorted(bucket["peer_ports"]),
            "services": sorted(bucket["services"]),
            "network_ids": network_ids,
            "sample_flow_ids": bucket["sample_flow_ids"],
            "sample_sna_flow_ids": bucket["sample_sna_flow_ids"],
            "max_duration_seconds": bucket["max_duration_seconds"],
            "rule_parameters": rule.parameters,
        },
    }


def _build_candidates(rules, host_peer, host_peer_port, peer_buckets):
    candidates = []
    for rule in rules:
        parameters = rule.parameters or {}
        if rule.rule_type == DetectionRuleType.LONG_SSH:
            threshold = int(parameters.get("min_duration_seconds", 1800))
            ports = {int(port) for port in parameters.get("ports", [22])}
            for (date, structure_id, host_ip, peer_ip, host_port), bucket in host_peer_port.items():
                is_ssh = host_port in ports or any(service.lower() == "ssh" for service in bucket["services"])
                if not is_ssh or bucket["max_duration_seconds"] < threshold:
                    continue
                item = _candidate(rule, date, structure_id, (host_ip, peer_ip, host_port), bucket, host_ip=host_ip, peer_ip=peer_ip, host_port=host_port)
                item["title"] = f"Communication SSH longue avec {peer_ip}"
                item["summary"] = f"Durée maximale {bucket['max_duration_seconds']} s vers {host_ip}:{host_port or '-'} (seuil {threshold} s)."
                candidates.append(item)

        elif rule.rule_type == DetectionRuleType.MALICIOUS_HIGH_VOLUME:
            threshold = int(parameters.get("min_total_bytes", 10_000_000))
            verdicts = set(parameters.get("verdicts", [ReputationVerdict.MALICIOUS]))
            for (date, structure_id, host_ip, peer_ip), bucket in host_peer.items():
                if bucket["reputation_verdict"] not in verdicts or bucket["total_bytes"] < threshold:
                    continue
                item = _candidate(rule, date, structure_id, (host_ip, peer_ip), bucket, host_ip=host_ip, peer_ip=peer_ip)
                item["title"] = f"Volume important avec l’IP malveillante {peer_ip}"
                item["summary"] = f"{bucket['total_bytes']} octets échangés avec {host_ip} (seuil {threshold})."
                candidates.append(item)

        elif rule.rule_type == DetectionRuleType.REPEATED_PEER:
            threshold = int(parameters.get("min_flow_count", 50))
            for (date, structure_id, host_ip, peer_ip), bucket in host_peer.items():
                if bucket["flow_count"] < threshold:
                    continue
                item = _candidate(rule, date, structure_id, (host_ip, peer_ip), bucket, host_ip=host_ip, peer_ip=peer_ip)
                item["title"] = f"Connexions répétées avec {peer_ip}"
                item["summary"] = f"{bucket['flow_count']} flows observés avec {host_ip} (seuil {threshold})."
                candidates.append(item)

        elif rule.rule_type == DetectionRuleType.SENSITIVE_PORT:
            ports = {int(port) for port in parameters.get("ports", [22, 23, 445, 3389, 5900, 5985, 5986])}
            min_flow_count = int(parameters.get("min_flow_count", 1))
            for (date, structure_id, host_ip, peer_ip, host_port), bucket in host_peer_port.items():
                if host_port not in ports or bucket["flow_count"] < min_flow_count:
                    continue
                item = _candidate(rule, date, structure_id, (host_ip, peer_ip, host_port), bucket, host_ip=host_ip, peer_ip=peer_ip, host_port=host_port)
                item["title"] = f"Activité externe sur le port sensible {host_port}"
                item["summary"] = f"{peer_ip} a communiqué avec {host_ip}:{host_port} dans {bucket['flow_count']} flow(s)."
                candidates.append(item)

        elif rule.rule_type == DetectionRuleType.MULTI_HOST_PEER:
            threshold = int(parameters.get("min_host_count", 5))
            verdicts = set(parameters.get("verdicts", [
                ReputationVerdict.MALICIOUS,
                ReputationVerdict.SUSPICIOUS,
                ReputationVerdict.UNKNOWN,
            ]))
            for (date, structure_id, peer_ip), bucket in peer_buckets.items():
                if len(bucket["host_ips"]) < threshold or bucket["reputation_verdict"] not in verdicts:
                    continue
                item = _candidate(rule, date, structure_id, (peer_ip,), bucket, peer_ip=peer_ip)
                item["title"] = f"Peer active sur plusieurs hôtes : {peer_ip}"
                item["summary"] = f"Cette peer a communiqué avec {len(bucket['host_ips'])} hôtes internes (seuil {threshold})."
                candidates.append(item)
    return candidates


def run_detections(payload: dict, progress_callback=None) -> dict:
    rules = DetectionRule.objects.filter(is_active=True)
    rule_ids = payload.get("rule_ids") or []
    if rule_ids:
        rules = rules.filter(id__in=rule_ids)
    rules = list(rules)
    flows = _scoped_flows(payload)
    total = flows.count()
    reputations = {item.ip_address: item for item in IPReputation.objects.all()}
    host_peer = defaultdict(_new_bucket)
    host_peer_port = defaultdict(_new_bucket)
    peer_buckets = defaultdict(_new_bucket)
    cidr_cache = {}

    for current, flow in enumerate(flows.iterator(chunk_size=1000), start=1):
        structure_id = flow.network.structure_id
        if structure_id not in cidr_cache:
            cidr_cache[structure_id] = internal_cidrs_for_structure(flow.network.structure)
        endpoint = _observation_endpoint(flow, cidr_cache[structure_id])
        if endpoint is None:
            continue
        peer_is_source = endpoint.peer_ip == flow.src_ip
        peer_port = flow.src_port if peer_is_source else flow.dst_port
        peer_country = flow.src_location if peer_is_source else flow.dst_location
        reputation = reputations.get(endpoint.peer_ip)
        date = flow.started_at.date()

        detailed_key = (date, structure_id, endpoint.host_ip, endpoint.peer_ip, endpoint.host_port)
        host_peer_key = (date, structure_id, endpoint.host_ip, endpoint.peer_ip)
        peer_key = (date, structure_id, endpoint.peer_ip)
        for bucket in (host_peer[host_peer_key], host_peer_port[detailed_key], peer_buckets[peer_key]):
            _add_flow(bucket, flow, endpoint, peer_port, reputation, peer_country)
        if progress_callback and (current % 1000 == 0 or current == total):
            progress_callback(current, total, f"Analyse de {current}/{total} flows")

    candidates = _build_candidates(rules, host_peer, host_peer_port, peer_buckets)
    created_count = 0
    updated_count = 0
    now = timezone.now()
    with transaction.atomic():
        for item in candidates:
            dedupe_key = item.pop("dedupe_key")
            rule = item.pop("rule")
            hit, created = DetectionHit.objects.update_or_create(
                dedupe_key=dedupe_key,
                defaults={"rule": rule, **item, "last_detected_at": now},
            )
            created_count += int(created)
            updated_count += int(not created)

    if progress_callback:
        progress_callback(total, total, f"{len(candidates)} détection(s) enregistrée(s)")
    return {
        "scope": payload.get("scope") or "all_flows",
        "flow_count": total,
        "rule_count": len(rules),
        "hit_count": len(candidates),
        "created_count": created_count,
        "updated_count": updated_count,
    }
