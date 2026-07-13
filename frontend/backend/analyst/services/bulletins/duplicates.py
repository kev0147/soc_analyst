import hashlib

from analyst.models import Bulletin


def build_ip_signature(ips: list[dict]) -> str:
    parts = sorted(f"{item['role']}:{item['ip_address']}:{item.get('port') or ''}" for item in ips)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest() if parts else ""


def _risk_id_set(bulletin: Bulletin) -> set[int]:
    return set(bulletin.risk_links.values_list("risk_id", flat=True))


def duplicate_summary(bulletin: Bulletin) -> dict:
    return {
        "id": bulletin.id,
        "reference": bulletin.reference,
        "severity": bulletin.severity,
        "status": bulletin.status,
        "created_at": bulletin.created_at.isoformat(),
        "sent_at": bulletin.sent_at.isoformat() if bulletin.sent_at else None,
        "risks": [link.risk.name for link in bulletin.risk_links.all()],
        "ips": [{"ip_address": item.ip_address, "role": item.role, "port": item.port} for item in bulletin.ip_addresses.all()],
    }


def find_duplicate_bulletins(structure_id: int, ips: list[dict], risk_ids: list[int], exclude_bulletin_id: int | None = None) -> list[dict]:
    ip_signature = build_ip_signature(ips)
    risk_set = set(risk_ids)
    if not ip_signature:
        return []

    candidates = Bulletin.objects.filter(
        structure_id=structure_id,
        ip_signature=ip_signature,
        deleted_at__isnull=True,
    ).prefetch_related("risk_links__risk", "ip_addresses")
    if exclude_bulletin_id:
        candidates = candidates.exclude(pk=exclude_bulletin_id)

    duplicates = []
    for bulletin in candidates:
        if _risk_id_set(bulletin) == risk_set:
            duplicates.append(duplicate_summary(bulletin))
    return duplicates


def _finding_signature_set(bulletin: Bulletin) -> set[tuple[int, int]]:
    return set(bulletin.findings.values_list("peer_observation_id", "risk_profile_id"))


def finding_duplicate_summary(bulletin: Bulletin) -> dict:
    return {
        "id": bulletin.id,
        "reference": bulletin.reference,
        "severity": bulletin.severity,
        "status": bulletin.status,
        "created_at": bulletin.created_at.isoformat(),
        "sent_at": bulletin.sent_at.isoformat() if bulletin.sent_at else None,
        "findings": [
            {
                "peer_observation_id": finding.peer_observation_id,
                "peer_ip": finding.peer_observation.peer_ip,
                "host_ip": finding.peer_observation.host_ip,
                "host_port": finding.peer_observation.host_port,
                "risk_profile_id": finding.risk_profile_id,
                "risk_name": finding.risk_profile.name,
            }
            for finding in bulletin.findings.all()
        ],
    }


def find_duplicate_bulletin_findings(
    structure_id: int,
    finding_pairs: set[tuple[int, int]],
    exclude_bulletin_id: int | None = None,
) -> list[dict]:
    if not finding_pairs:
        return []

    observation_ids = {pair[0] for pair in finding_pairs}
    candidates = (
        Bulletin.objects.filter(
            structure_id=structure_id,
            deleted_at__isnull=True,
            findings__peer_observation_id__in=observation_ids,
        )
        .distinct()
        .prefetch_related(
            "findings",
            "findings__peer_observation",
            "findings__peer_observation__peer_reputation",
            "findings__risk_profile",
        )
    )
    if exclude_bulletin_id:
        candidates = candidates.exclude(pk=exclude_bulletin_id)

    duplicates = []
    for bulletin in candidates:
        if _finding_signature_set(bulletin) == finding_pairs:
            duplicates.append(finding_duplicate_summary(bulletin))
    return duplicates
