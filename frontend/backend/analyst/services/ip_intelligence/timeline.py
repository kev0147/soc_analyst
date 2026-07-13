import ipaddress
from collections import defaultdict

from django.db.models import Q
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError

from analyst.models import Bulletin, BulletinFinding, BulletinIP, BulletinResponse, Flow


DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def _int_param(params, name: str) -> int | None:
    value = params.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({name: "Doit être un entier."}) from exc


def _date_param(params, name: str):
    value = params.get(name)
    if value in (None, ""):
        return None
    parsed = parse_datetime(value)
    if not parsed:
        raise ValidationError({name: "Date invalide. Utilisez un format ISO-8601."})
    return parsed


def _limit(params) -> int:
    value = _int_param(params, "limit")
    if value is None:
        return DEFAULT_LIMIT
    if value < 1:
        raise ValidationError({"limit": "Doit être supérieur à 0."})
    return min(value, MAX_LIMIT)


def _validate_ip(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValidationError({"ip": "Adresse IP invalide."}) from exc
    if address.version != 4:
        raise ValidationError({"ip": "Le MVP accepte uniquement IPv4."})
    return str(address)


def _flow_side(flow: Flow, ip: str) -> str:
    if flow.src_ip == ip and flow.dst_ip == ip:
        return "both"
    if flow.src_ip == ip:
        return "source"
    if flow.dst_ip == ip:
        return "destination"
    return "unknown"


def _flow_summary(flow: Flow, ip: str) -> dict:
    return {
        "id": flow.id,
        "type": "flow",
        "timestamp": flow.started_at.isoformat(),
        "structure": {
            "id": flow.network.structure_id,
            "code": flow.network.structure.code,
            "name": flow.network.structure.name,
        },
        "network": {"id": flow.network_id, "name": flow.network.name},
        "sna_flow_id": flow.sna_flow_id,
        "side": _flow_side(flow, ip),
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "service": flow.service,
        "application": flow.application,
        "direction": flow.direction,
        "total_bytes": flow.total_bytes,
        "total_packets": flow.total_packets,
    }


def _bulletin_summary(bulletin: Bulletin, ip_link: BulletinIP | None = None, finding: BulletinFinding | None = None) -> dict:
    return {
        "id": bulletin.id,
        "type": "bulletin",
        "timestamp": (bulletin.sent_at or bulletin.created_at).isoformat(),
        "reference": bulletin.reference,
        "structure": {
            "id": bulletin.structure_id,
            "code": bulletin.structure.code,
            "name": bulletin.structure.name,
        },
        "severity": bulletin.severity,
        "status": bulletin.status,
        "ip_role": ip_link.role if ip_link else None,
        "risks": [link.risk.name for link in bulletin.risk_links.all()],
        "findings": [
            {
                "peer_ip": item.peer_observation.peer_ip,
                "host_ip": item.peer_observation.host_ip,
                "host_port": item.peer_observation.host_port,
                "host_service": item.peer_observation.host_service,
                "risk_name": item.risk_profile.name,
                "severity": item.severity,
            }
            for item in bulletin.findings.all()
        ],
        "matched_finding_id": finding.id if finding else None,
        "bulletin_types": [link.bulletin_type.name for link in bulletin.type_links.all()],
    }


def _response_summary(response: BulletinResponse) -> dict:
    bulletin = response.bulletin
    return {
        "id": response.id,
        "type": "response",
        "timestamp": response.received_at.isoformat(),
        "bulletin": {
            "id": bulletin.id,
            "reference": bulletin.reference,
            "severity": bulletin.severity,
            "status": bulletin.status,
        },
        "structure": {
            "id": bulletin.structure_id,
            "code": bulletin.structure.code,
            "name": bulletin.structure.name,
        },
        "respondent_name": response.respondent_name,
        "respondent_email": response.respondent_email,
        "content": response.content,
    }


def _conversation_groups(flows, ip: str) -> list[dict]:
    groups = defaultdict(lambda: {
        "flow_count": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "first_seen": None,
        "last_seen": None,
        "directions": set(),
        "services": set(),
        "applications": set(),
    })

    for flow in flows:
        other_ip = flow.dst_ip if flow.src_ip == ip else flow.src_ip
        hour = flow.started_at.replace(minute=0, second=0, microsecond=0)
        key = (flow.conversation_ip_a, flow.conversation_ip_b, hour)
        group = groups[key]
        group["conversation_ip_a"] = flow.conversation_ip_a
        group["conversation_ip_b"] = flow.conversation_ip_b
        group["other_ip"] = other_ip
        group["hour"] = hour
        group["flow_count"] += 1
        group["total_bytes"] += flow.total_bytes or 0
        group["total_packets"] += flow.total_packets or 0
        group["first_seen"] = flow.started_at if group["first_seen"] is None or flow.started_at < group["first_seen"] else group["first_seen"]
        group["last_seen"] = flow.started_at if group["last_seen"] is None or flow.started_at > group["last_seen"] else group["last_seen"]
        if flow.direction:
            group["directions"].add(flow.direction)
        if flow.service:
            group["services"].add(flow.service)
        if flow.application:
            group["applications"].add(flow.application)

    rows = []
    for group in groups.values():
        rows.append({
            "conversation_ip_a": group["conversation_ip_a"],
            "conversation_ip_b": group["conversation_ip_b"],
            "other_ip": group["other_ip"],
            "hour": group["hour"].isoformat(),
            "flow_count": group["flow_count"],
            "total_bytes": group["total_bytes"],
            "total_packets": group["total_packets"],
            "first_seen": group["first_seen"].isoformat(),
            "last_seen": group["last_seen"].isoformat(),
            "directions": sorted(group["directions"]),
            "services": sorted(group["services"]),
            "applications": sorted(group["applications"]),
        })
    return sorted(rows, key=lambda item: item["hour"], reverse=True)


def build_ip_timeline(ip: str, params) -> dict:
    ip = _validate_ip(ip)
    limit = _limit(params)
    structure_id = _int_param(params, "structure_id")
    network_id = _int_param(params, "network_id")
    started_from = _date_param(params, "started_from")
    started_to = _date_param(params, "started_to")

    flows = Flow.objects.select_related("network", "network__structure").filter(Q(src_ip=ip) | Q(dst_ip=ip))
    if structure_id is not None:
        flows = flows.filter(network__structure_id=structure_id)
    if network_id is not None:
        flows = flows.filter(network_id=network_id)
    if started_from is not None:
        flows = flows.filter(started_at__gte=started_from)
    if started_to is not None:
        flows = flows.filter(started_at__lte=started_to)
    flows = list(flows.order_by("-started_at", "-id")[:limit])

    bulletin_ips = BulletinIP.objects.select_related("bulletin", "bulletin__structure").filter(
        ip_address=ip,
        bulletin__deleted_at__isnull=True,
    )
    if structure_id is not None:
        bulletin_ips = bulletin_ips.filter(bulletin__structure_id=structure_id)
    bulletin_ips = list(
        bulletin_ips.prefetch_related(
            "bulletin__risk_links__risk",
            "bulletin__type_links__bulletin_type",
        ).order_by("-bulletin__reference_year", "-bulletin__sequence_number")[:limit]
    )

    bulletin_findings = BulletinFinding.objects.select_related(
        "bulletin",
        "bulletin__structure",
        "peer_observation",
        "peer_observation__peer_reputation",
        "risk_profile",
    ).filter(
        Q(peer_observation__peer_reputation__ip_address=ip) | Q(peer_observation__host_ip=ip),
        bulletin__deleted_at__isnull=True,
    )
    if structure_id is not None:
        bulletin_findings = bulletin_findings.filter(bulletin__structure_id=structure_id)
    bulletin_findings = list(
        bulletin_findings.prefetch_related(
            "bulletin__risk_links__risk",
            "bulletin__type_links__bulletin_type",
            "bulletin__findings",
            "bulletin__findings__peer_observation",
            "bulletin__findings__peer_observation__peer_reputation",
            "bulletin__findings__risk_profile",
        ).order_by("-bulletin__reference_year", "-bulletin__sequence_number")[:limit]
    )

    bulletins = [item.bulletin for item in bulletin_ips]
    bulletin_by_id = {item.bulletin_id: item for item in bulletin_ips}
    finding_by_bulletin_id = {item.bulletin_id: item for item in bulletin_findings}
    for finding in bulletin_findings:
        if finding.bulletin_id not in bulletin_by_id:
            bulletins.append(finding.bulletin)
    responses = BulletinResponse.objects.select_related("bulletin", "bulletin__structure").filter(
        bulletin_id__in={bulletin.id for bulletin in bulletins}
    ).order_by("-received_at", "-id")[:limit]

    flow_items = [_flow_summary(flow, ip) for flow in flows]
    bulletin_items = [
        _bulletin_summary(bulletin, bulletin_by_id.get(bulletin.id), finding_by_bulletin_id.get(bulletin.id))
        for bulletin in bulletins
    ]
    response_items = [_response_summary(response) for response in responses]
    timeline = sorted(
        flow_items + bulletin_items + response_items,
        key=lambda item: item["timestamp"],
        reverse=True,
    )

    return {
        "ip": ip,
        "filters": {
            "structure_id": structure_id,
            "network_id": network_id,
            "started_from": started_from.isoformat() if started_from else None,
            "started_to": started_to.isoformat() if started_to else None,
            "limit": limit,
        },
        "counts": {
            "flows": len(flow_items),
            "bulletins": len(bulletin_items),
            "responses": len(response_items),
            "timeline": len(timeline),
            "conversation_groups": len(_conversation_groups(flows, ip)),
        },
        "flows": flow_items,
        "bulletins": bulletin_items,
        "responses": response_items,
        "conversation_groups": _conversation_groups(flows, ip),
        "timeline": timeline,
    }
