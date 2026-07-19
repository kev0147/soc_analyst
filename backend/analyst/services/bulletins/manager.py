from django.db import transaction

from analyst.models import (
    Bulletin,
    BulletinActivity,
    BulletinFinding,
    BulletinIP,
    BulletinRecommendation,
    BulletinRisk,
)

from .duplicates import find_duplicate_bulletin_findings, find_duplicate_bulletins


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@transaction.atomic
def create_bulletin_with_links(data: dict, user, force_duplicate: bool = False) -> tuple[Bulletin | None, list[dict]]:
    duplicates = find_duplicate_bulletins(
        structure_id=data["structure"].id,
        ips=data["ips"],
        risk_ids=[risk.id for risk in data["risks"]],
    )
    if duplicates and not force_duplicate:
        return None, duplicates

    bulletin = Bulletin.objects.create(
        structure=data["structure"],
        external_reference=data.get("external_reference", ""),
        severity=data["severity"],
        status=data.get("status") or Bulletin._meta.get_field("status").default,
        sent_at=data.get("sent_at"),
        created_by=user,
        updated_by=user,
    )

    for item in data["ips"]:
        BulletinIP.objects.create(
            bulletin=bulletin,
            ip_address=item["ip_address"],
            role=item["role"],
            port=item.get("port"),
            note=item.get("note", ""),
        )
    for activity in data["activities"]:
        BulletinActivity.objects.create(bulletin=bulletin, activity=activity)
    for risk in data["risks"]:
        BulletinRisk.objects.create(bulletin=bulletin, risk=risk)
    for recommendation in data["recommendations"]:
        BulletinRecommendation.objects.create(bulletin=bulletin, recommendation=recommendation)

    bulletin.refresh_ip_signature()
    return bulletin, duplicates


def _highest_severity(risk_profiles):
    if not risk_profiles:
        return Bulletin._meta.get_field("severity").default
    return max(
        (profile.default_severity for profile in risk_profiles),
        key=lambda severity: SEVERITY_RANK.get(severity, 0),
    )


@transaction.atomic
def create_bulletin_from_findings(data: dict, user, force_duplicate: bool = False) -> tuple[Bulletin | None, list[dict]]:
    observations = list(data["peer_observations"])
    risk_profiles = list(data["risk_profiles"])
    risk_indicator = data.get("risk_indicator")
    profile_ports = {
        profile.id: {item.port for item in profile.port_services.all()}
        for profile in risk_profiles
    }
    compatible_pairs = [
        (observation, risk_profile)
        for observation in observations
        for risk_profile in risk_profiles
        if not profile_ports[risk_profile.id] or observation.host_port in profile_ports[risk_profile.id]
    ]
    finding_pairs = {(observation.id, risk_profile.id) for observation, risk_profile in compatible_pairs}

    duplicates = find_duplicate_bulletin_findings(
        structure_id=data["structure"].id,
        finding_pairs=finding_pairs,
    )
    if duplicates and not force_duplicate:
        return None, duplicates

    bulletin = Bulletin.objects.create(
        structure=data["structure"],
        external_reference=data.get("external_reference", ""),
        severity=data.get("severity") or _highest_severity(risk_profiles),
        status=data.get("status") or Bulletin._meta.get_field("status").default,
        sent_at=data.get("sent_at"),
        created_by=user,
        updated_by=user,
    )

    for activity in {profile.activity for _, profile in compatible_pairs}:
        BulletinActivity.objects.create(bulletin=bulletin, activity=activity)

    for observation, risk_profile in compatible_pairs:
        BulletinFinding.objects.create(
            bulletin=bulletin,
            peer_observation=observation,
            risk_profile=risk_profile,
            risk_indicator=risk_indicator,
            severity=data.get("severity") or risk_profile.default_severity,
        )

    return bulletin, duplicates
