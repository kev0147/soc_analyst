import ipaddress
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from analyst.models import ActivityCatalog, Bulletin, RiskCatalog, Structure
from analyst.models.choices import BulletinIPRole, BulletinSeverity, BulletinStatus
from analyst.services.bulletins.manager import create_bulletin_with_links
from analyst.services.excel_reader import read_xlsx_sheets


LEGACY_WORKBOOK_SCHEMA = {
    "alerte": {"date alerte", "trimestre", "ref alerte", "serverite", "structure"},
    "type alerte": {"date alerte", "trimestre", "ref alerte", "type alerte"},
    "adr alerte": {"date alerte", "trimestre", "ref alerte", "adr source"},
    "service alerte": {
        "date alerte",
        "trimestre",
        "ref alerte",
        "num port",
        "nom service",
        "categorie service",
    },
}


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
    for pattern in ("%m/%d/%Y", "%m/%d/%Y %H:%M", "%d/%m/%Y", "%d-%m-%Y", "%d/%m/%Y %H:%M"):
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


def _structure_code(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = "".join(char for char in normalized if not unicodedata.combining(char))
    base = re.sub(r"[^A-Z0-9]+", "_", ascii_value.upper()).strip("_")[:32] or "STRUCTURE"
    code = base
    suffix = 2
    while Structure.objects.filter(code__iexact=code).exists():
        suffix_text = f"_{suffix}"
        code = f"{base[:32 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    return code


def _structure(value: str, default_code: str | None, create_missing: bool = False):
    lookup = value or default_code
    if not lookup:
        raise ValueError("Structure manquante.")
    structure = Structure.objects.filter(code__iexact=lookup).first()
    if not structure:
        structure = Structure.objects.filter(name__iexact=lookup).first()
    if not structure:
        if not create_missing:
            raise ValueError(f"Structure introuvable : {lookup}.")
        structure = Structure.objects.create(
            name=lookup,
            code=_structure_code(lookup),
            description="Structure créée automatiquement pendant l’import des bulletins historiques.",
            is_active=True,
        )
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
    create_missing_structures: bool = False,
) -> dict:
    path = Path(path)
    if path.suffix.lower() != ".xlsx":
        raise ValueError("Le fichier historique doit être au format .xlsx.")
    sheets = read_xlsx_sheets(path)
    normalized_sheets = {_normalize(name): rows for name, rows in sheets.items()}
    missing_sheets = sorted(set(LEGACY_WORKBOOK_SCHEMA) - set(normalized_sheets))
    if missing_sheets:
        raise ValueError("Feuille(s) obligatoire(s) manquante(s) : " + ", ".join(missing_sheets) + ".")

    invalid_sheets = []
    for sheet_name, expected_headers in LEGACY_WORKBOOK_SCHEMA.items():
        rows = normalized_sheets[sheet_name]
        if not rows:
            continue
        actual_headers = {_normalize(header) for header in rows[0]}
        missing_headers = sorted(expected_headers - actual_headers)
        if missing_headers:
            invalid_sheets.append(f"{sheet_name}: {', '.join(missing_headers)}")
    if invalid_sheets:
        raise ValueError("Colonne(s) obligatoire(s) manquante(s) — " + "; ".join(invalid_sheets) + ".")

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
        "already_imported": 0,
        "ignored_rows": ignored_rows,
        "warnings": [],
        "rejected": [],
    }
    historical_risk, _ = RiskCatalog.objects.get_or_create(
        name="Risque historique non renseigné",
        defaults={"description": "Le fichier historique ne contenait pas de risque exploitable."},
    )

    for reference, rows in groups.items():
        try:
            if Bulletin.objects.filter(external_reference__iexact=reference).exists():
                result["already_imported"] += 1
                continue
            structure_value = next((_value(row, "structure", "structure_code") for _, _, row in rows if _value(row, "structure", "structure_code")), "")
            severity_value = next((_value(row, "serverite", "severite", "sévérité", "criticite", "criticité") for _, _, row in rows if _value(row, "serverite", "severite", "sévérité", "criticite", "criticité")), "")
            date_value = next((_value(row, "date_alert", "date alerte", "date") for _, _, row in rows if _value(row, "date_alert", "date alerte", "date")), "")
            types = set()
            addresses = {}
            ports = defaultdict(lambda: {"services": set(), "categories": set()})
            invalid_address_count = 0
            for sheet_name, row_number, row in rows:
                types.update(_split(_value(row, "type_alerte", "type alerte")))
                address = _value(row, "adr_source", "adresse source", "ip", "ip_address")
                if address:
                    try:
                        normalized_address = str(ipaddress.ip_address(address))
                    except ValueError:
                        invalid_address_count += 1
                        result["warnings"].append({
                            "reference": reference,
                            "sheet": sheet_name,
                            "row": row_number,
                            "field": "adr_source",
                            "value": address,
                            "reason": "Adresse IP invalide",
                        })
                    else:
                        addresses[normalized_address] = _value(row, "adr_pays", "pays", "country")
                elif _normalize(sheet_name) == "adr alerte":
                    result["warnings"].append({
                        "reference": reference,
                        "sheet": sheet_name,
                        "row": row_number,
                        "field": "adr_source",
                        "value": "",
                        "reason": "Adresse IP vide",
                    })
                raw_port = _value(row, "num_port", "port")
                port = _port(raw_port)
                if port is not None:
                    service = _value(row, "nom_service", "service")
                    category = _value(row, "Categorie_Service", "categorie service")
                    if service:
                        ports[port]["services"].add(service)
                    if category:
                        ports[port]["categories"].add(category)
                elif raw_port:
                    result["warnings"].append({
                        "reference": reference,
                        "sheet": sheet_name,
                        "row": row_number,
                        "field": "num_port",
                        "value": raw_port,
                        "reason": "Port invalide (valeur attendue entre 0 et 65535)",
                    })
            if not addresses:
                suffix = f" ({invalid_address_count} valeur(s) invalide(s), voir le rapport)." if invalid_address_count else ""
                raise ValueError("Aucune adr_source valide." + suffix)

            ips = []
            for address, country in addresses.items():
                if ports:
                    for port, port_info in sorted(ports.items()):
                        services = ", ".join(sorted(port_info["services"]))
                        categories = ", ".join(sorted(port_info["categories"]))
                        notes = [item for item in (f"Pays: {country}" if country else "", f"Service: {services}" if services else "", f"Catégorie: {categories}" if categories else "") if item]
                        ips.append({"ip_address": address, "role": BulletinIPRole.SOURCE, "port": port, "note": " — ".join(notes)})
                else:
                    ips.append({"ip_address": address, "role": BulletinIPRole.SOURCE, "port": None, "note": f"Pays: {country}" if country else ""})

            data = {
                "structure": _structure(
                    structure_value,
                    default_structure_code,
                    create_missing=create_missing_structures,
                ),
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
