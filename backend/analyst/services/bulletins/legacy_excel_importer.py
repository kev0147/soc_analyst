import ipaddress
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from analyst.models import ActivityCatalog, RiskCatalog, Structure
from analyst.models.choices import BulletinIPRole, BulletinSeverity, BulletinStatus
from analyst.services.bulletins.manager import create_bulletin_with_links
from analyst.services.excel_reader import read_xlsx_sheets


def _normalize(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(char for char in value if not unicodedata.combining(char))
    return " ".join(value.strip().lower().replace("_", " ").split())


def _value(row: dict, *aliases: str) -> str:
    normalized = {_normalize(key): str(value or "").strip() for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(_normalize(alias), "")
        if value:
            return value
    return ""


def _split(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[;\n,]+", value or "") if item.strip()]


def _severity(value: str) -> str:
    mapping = {
        "faible": BulletinSeverity.LOW,
        "moyen": BulletinSeverity.MEDIUM,
        "moyenne": BulletinSeverity.MEDIUM,
        "eleve": BulletinSeverity.HIGH,
        "elevee": BulletinSeverity.HIGH,
        "critique": BulletinSeverity.CRITICAL,
    }
    return mapping.get(_normalize(value), BulletinSeverity.HIGH)


def _date(value: str):
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed:
        return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)
    parsed_date = parse_date(value)
    if parsed_date:
        return timezone.make_aware(datetime.combine(parsed_date, datetime.min.time()))
    for pattern in ("%d/%m/%Y", "%d-%m-%Y", "%d/%m/%Y %H:%M"):
        try:
            return timezone.make_aware(datetime.strptime(value, pattern))
        except ValueError:
            pass
    try:
        serial = float(value)
        return timezone.make_aware(datetime(1899, 12, 30) + timedelta(days=serial))
    except ValueError:
        return None


def _port(value: str):
    match = re.search(r"\d+", value or "")
    if not match:
        return None
    port = int(match.group())
    return port if 0 <= port <= 65535 else None


def _structure(value: str, default_code: str | None):
    lookup = value or default_code
    if not lookup:
        raise ValueError("Structure manquante.")
    structure = Structure.objects.filter(code__iexact=lookup).first()
    if not structure:
        structure = Structure.objects.filter(name__iexact=lookup).first()
    if not structure:
        raise ValueError(f"Structure introuvable : {lookup}.")
    return structure


def _catalog(model, names: set[str]):
    result = []
    for name in sorted(names):
        item, _ = model.objects.get_or_create(name=name, defaults={"description": ""})
        result.append(item)
    return result


@transaction.atomic
def import_legacy_bulletins_workbook(
    path: str | Path,
    user,
    default_structure_code: str | None = None,
    force_duplicates: bool = False,
    dry_run: bool = False,
) -> dict:
    path = Path(path)
    if path.suffix.lower() != ".xlsx":
        raise ValueError("Le fichier historique doit être au format .xlsx.")
    sheets = read_xlsx_sheets(path)
    groups = defaultdict(list)
    ignored_rows = 0
    for sheet_name, rows in sheets.items():
        for row_number, row in enumerate(rows, start=2):
            reference = _value(row, "ref_alerte", "reference", "ref")
            if reference:
                groups[reference].append((sheet_name, row_number, row))
            else:
                ignored_rows += 1

    result = {
        "sheet_count": len(sheets),
        "group_count": len(groups),
        "created": 0,
        "duplicates": 0,
        "ignored_rows": ignored_rows,
        "rejected": [],
    }
    historical_risk, _ = RiskCatalog.objects.get_or_create(
        name="Risque historique non renseigné",
        defaults={"description": "Le fichier historique ne contenait pas de risque exploitable."},
    )

    for reference, rows in groups.items():
        try:
            structure_value = next((_value(row, "structure", "structure_code") for _, _, row in rows if _value(row, "structure", "structure_code")), "")
            severity_value = next((_value(row, "severite", "sévérité", "criticite", "criticité") for _, _, row in rows if _value(row, "severite", "sévérité", "criticite", "criticité")), "")
            date_value = next((_value(row, "date_alert", "date alerte", "date") for _, _, row in rows if _value(row, "date_alert", "date alerte", "date")), "")
            types = set()
            addresses = {}
            ports = []
            for _, _, row in rows:
                types.update(_split(_value(row, "type_alerte", "type alerte")))
                address = _value(row, "adr_source", "adresse source", "ip", "ip_address")
                if address:
                    ipaddress.ip_address(address)
                    addresses[address] = _value(row, "adr_pays", "pays", "country")
                port = _port(_value(row, "num_port", "port"))
                if port is not None:
                    ports.append({
                        "port": port,
                        "service": _value(row, "nom_service", "service"),
                        "category": _value(row, "Categorie_Service", "categorie service"),
                    })
            if not addresses:
                raise ValueError("Aucune adr_source valide.")

            unique_ports = {(item["port"], item["service"], item["category"]): item for item in ports}.values()
            ips = []
            for address, country in addresses.items():
                if unique_ports:
                    for port_info in unique_ports:
                        notes = [item for item in (f"Pays: {country}" if country else "", f"Service: {port_info['service']}" if port_info["service"] else "", f"Catégorie: {port_info['category']}" if port_info["category"] else "") if item]
                        ips.append({"ip_address": address, "role": BulletinIPRole.SOURCE, "port": port_info["port"], "note": " — ".join(notes)})
                else:
                    ips.append({"ip_address": address, "role": BulletinIPRole.SOURCE, "port": None, "note": f"Pays: {country}" if country else ""})

            data = {
                "structure": _structure(structure_value, default_structure_code),
                "external_reference": reference,
                "severity": _severity(severity_value),
                "status": BulletinStatus.SENT,
                "sent_at": _date(date_value),
                "ips": ips,
                "risks": [historical_risk],
                "activities": _catalog(ActivityCatalog, types),
                "recommendations": [],
            }
            bulletin, duplicates = create_bulletin_with_links(data, user, force_duplicate=force_duplicates)
            if bulletin is None:
                result["duplicates"] += 1
                result["rejected"].append({"reference": reference, "reason": "Doublon exact détecté."})
            else:
                result["created"] += 1
        except Exception as exc:
            result["rejected"].append({"reference": reference, "reason": str(exc)})
    if dry_run:
        transaction.set_rollback(True)
    result["dry_run"] = dry_run
    return result
