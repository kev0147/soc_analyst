import csv
import ipaddress
from collections import defaultdict
from pathlib import Path

from django.db import transaction
from django.utils.dateparse import parse_datetime

from analyst.models import ActivityCatalog, RecommendationCatalog, RiskCatalog, Structure
from analyst.models.choices import BulletinIPRole, BulletinSeverity, BulletinStatus
from analyst.services.bulletins import create_bulletin_with_links
from analyst.services.excel_reader import read_xlsx_rows


ALIASES = {
    "bulletin_ref": {"bulletin_ref", "reference", "ref", "id", "id bulletin", "bulletin"},
    "structure": {"structure", "structure_code", "code structure", "organisation", "organization"},
    "ip_address": {"ip", "ip_address", "adresse ip", "adresse_ip", "peer", "peer_ip", "host_ip"},
    "role": {"role", "type ip", "sens", "host/peer", "host_peer"},
    "port": {"port", "ports", "dst_port", "peer_port"},
    "severity": {"severity", "gravite", "gravité", "niveau", "criticite", "criticité"},
    "status": {"status", "statut"},
    "risks": {"risks", "risk", "risque", "risques"},
    "types": {"types", "type", "bulletin_type", "bulletin types", "categorie", "catégorie"},
    "recommendations": {"recommendations", "recommendation", "recommandations", "recommandation"},
    "sent_at": {"sent_at", "date", "date_envoi", "envoye_le", "envoyé_le"},
    "note": {"note", "commentaire", "comments", "description"},
}


def _normalize_header(header: str) -> str:
    return " ".join(str(header or "").strip().lower().replace("_", " ").split())


def _row_value(row: dict[str, str], key: str) -> str:
    normalized = {_normalize_header(header): value for header, value in row.items()}
    for alias in ALIASES[key]:
        value = normalized.get(_normalize_header(alias))
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _split_values(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").replace("\n", ";").replace(",", ";").split(";") if item.strip()]


def _role(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"host", "hote", "hôte", "source", "src", "interne", "internal"}:
        return BulletinIPRole.SOURCE
    if normalized in {"peer", "destination", "dst", "dest", "externe", "external"}:
        return BulletinIPRole.DESTINATION
    return BulletinIPRole.DESTINATION


def _severity(value: str) -> str:
    normalized = str(value or "").strip().lower()
    mapping = {
        "low": BulletinSeverity.LOW,
        "faible": BulletinSeverity.LOW,
        "medium": BulletinSeverity.MEDIUM,
        "moyen": BulletinSeverity.MEDIUM,
        "moyenne": BulletinSeverity.MEDIUM,
        "high": BulletinSeverity.HIGH,
        "eleve": BulletinSeverity.HIGH,
        "élevé": BulletinSeverity.HIGH,
        "élevée": BulletinSeverity.HIGH,
        "critical": BulletinSeverity.CRITICAL,
        "critique": BulletinSeverity.CRITICAL,
    }
    return mapping.get(normalized, BulletinSeverity.HIGH)


def _status(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in BulletinStatus.values else BulletinStatus.DRAFT


def _port(value: str):
    if not value:
        return None
    try:
        parsed = int(float(str(value).strip()))
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 65535 else None


def _catalog_items(model, names: list[str]):
    items = []
    for name in names:
        item, _ = model.objects.get_or_create(name=name, defaults={"description": ""})
        items.append(item)
    return items


def _structure(value: str, default_code: str | None = None):
    lookup = value or default_code
    if not lookup:
        raise ValueError("Structure manquante.")
    return Structure.objects.get(code__iexact=lookup.strip())


def _load_rows(path: str | Path) -> list[dict[str, str]]:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    return read_xlsx_rows(path)


@transaction.atomic
def import_bulletins_from_excel(path: str | Path, user, default_structure_code: str | None = None, force_duplicates: bool = False) -> dict:
    rows = _load_rows(path)
    groups = defaultdict(list)
    rejected = []
    for index, row in enumerate(rows, start=2):
        reference = _row_value(row, "bulletin_ref") or f"row-{index}"
        groups[reference].append((index, row))

    created = 0
    duplicates = 0
    for reference, group_rows in groups.items():
        try:
            first_row = group_rows[0][1]
            ips = []
            risks = set()
            types = set()
            recommendations = set()
            for row_number, row in group_rows:
                ip = _row_value(row, "ip_address")
                if not ip:
                    raise ValueError(f"Ligne {row_number}: IP manquante.")
                ipaddress.ip_address(ip)
                ips.append({
                    "ip_address": ip,
                    "role": _role(_row_value(row, "role")),
                    "port": _port(_row_value(row, "port")),
                    "note": _row_value(row, "note"),
                })
                risks.update(_split_values(_row_value(row, "risks")))
                types.update(_split_values(_row_value(row, "types")))
                recommendations.update(_split_values(_row_value(row, "recommendations")))
            if not risks:
                risks.add("Risque non précisé")
            data = {
                "structure": _structure(_row_value(first_row, "structure"), default_structure_code),
                "severity": _severity(_row_value(first_row, "severity")),
                "status": _status(_row_value(first_row, "status")),
                "sent_at": parse_datetime(_row_value(first_row, "sent_at")) if _row_value(first_row, "sent_at") else None,
                "ips": ips,
                "risks": _catalog_items(RiskCatalog, sorted(risks)),
                "activities": _catalog_items(ActivityCatalog, sorted(types)),
                "recommendations": _catalog_items(RecommendationCatalog, sorted(recommendations)),
            }
            bulletin, found_duplicates = create_bulletin_with_links(data, user, force_duplicate=force_duplicates)
            if bulletin is None:
                duplicates += 1
                rejected.append({"reference": reference, "reason": "Doublon exact détecté", "duplicates": found_duplicates})
            else:
                created += 1
        except Exception as exc:
            rejected.append({"reference": reference, "reason": str(exc)})

    return {"row_count": len(rows), "group_count": len(groups), "created": created, "duplicates": duplicates, "rejected": rejected}
