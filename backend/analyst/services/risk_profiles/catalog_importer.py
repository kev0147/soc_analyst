import csv
import hashlib
import re
import unicodedata
from pathlib import Path

from django.db import transaction

from analyst.models import (
    ActivityCatalog,
    RiskIndicator,
    RiskProfile,
    RiskProfileIndicator,
    RiskProfilePortService,
)
from analyst.models.choices import BulletinSeverity
from analyst.services.excel_reader import read_xlsx_rows


REQUIRED_COLUMNS = {
    "activity": "ACTIVITÉS",
    "port_services": "PORTS/SERVICES",
    "risk": "RISQUES",
    "impact": "IMPACTS",
    "indicators": "IOCS",
    "recommendation": "RECOMMANDATIONS",
    "severity": "CRITICITÉ",
}


def _normalize(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(char for char in value if not unicodedata.combining(char))
    return " ".join(value.strip().lower().replace("_", " ").split())


def _clean(value: str) -> str:
    return "\n".join(line.strip() for line in str(value or "").replace("\r", "").split("\n") if line.strip())


def _mapped_row(row: dict[str, str]) -> dict[str, str]:
    normalized = {_normalize(header): value for header, value in row.items()}
    mapped = {}
    missing = []
    for key, label in REQUIRED_COLUMNS.items():
        normalized_label = _normalize(label)
        if normalized_label not in normalized:
            missing.append(label)
        mapped[key] = _clean(normalized.get(normalized_label, ""))
    if missing:
        raise ValueError(f"Colonnes manquantes : {', '.join(missing)}.")
    return mapped


def _expand_ports(expression: str) -> list[int]:
    parts = [part.strip() for part in re.split(r"\s*/\s*", expression) if part.strip()]
    if not parts:
        return []
    first = parts[0]
    ports = [int(first)]
    for part in parts[1:]:
        if len(part) < len(first):
            part = first[: len(first) - len(part)] + part
        ports.append(int(part))
    return ports


def parse_port_services(value: str) -> list[dict]:
    entries = []
    seen = set()
    pattern = re.compile(r"(\d+(?:\s*/\s*\d+)*)\s*(?:\(([^)]+)\))?")
    for match in pattern.finditer(value or ""):
        service = " ".join((match.group(2) or "").strip().split())
        for port in _expand_ports(match.group(1)):
            if not 0 <= port <= 65535:
                raise ValueError(f"Port hors plage : {port}.")
            key = (port, service.casefold())
            if key not in seen:
                entries.append({"port": port, "service": service})
                seen.add(key)
    if not entries:
        raise ValueError("Aucun port valide trouvé dans PORTS/SERVICES.")
    return entries


def parse_indicators(value: str) -> list[str]:
    values = []
    seen = set()
    for item in re.split(r"(?:\n|;|\u2022)+", value or ""):
        cleaned = " ".join(item.strip(" -\t").split())
        key = cleaned.casefold()
        if cleaned and key not in seen:
            values.append(cleaned)
            seen.add(key)
    if not values:
        raise ValueError("Aucun IOC renseigné.")
    return values


def parse_severity(value: str) -> str:
    mapping = {
        "faible": BulletinSeverity.LOW,
        "low": BulletinSeverity.LOW,
        "moyen": BulletinSeverity.MEDIUM,
        "moyenne": BulletinSeverity.MEDIUM,
        "medium": BulletinSeverity.MEDIUM,
        "eleve": BulletinSeverity.HIGH,
        "elevee": BulletinSeverity.HIGH,
        "high": BulletinSeverity.HIGH,
        "critique": BulletinSeverity.CRITICAL,
        "critical": BulletinSeverity.CRITICAL,
    }
    severity = mapping.get(_normalize(value))
    if not severity:
        raise ValueError(f"Criticité inconnue : {value or '(vide)' }.")
    return severity


def _source_key(row: dict, ports: list[dict], indicators: list[str]) -> str:
    signature = "|".join((
        _normalize(row["activity"]),
        _normalize(row["risk"]),
        ",".join(f"{item['port']}:{_normalize(item['service'])}" for item in ports),
        ",".join(sorted(_normalize(item) for item in indicators)),
    ))
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


def _load_rows(path: Path, sheet_index: int) -> list[dict[str, str]]:
    if path.suffix.lower() == ".xlsx":
        return read_xlsx_rows(path, sheet_index=sheet_index)
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;")
            except csv.Error:
                dialect = csv.excel
            return list(csv.DictReader(handle, dialect=dialect))
    raise ValueError("Format non pris en charge. Utilisez .xlsx ou .csv.")


def import_risk_profiles_catalog(path: str | Path, sheet_index: int = 1, dry_run: bool = False) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    rows = _load_rows(path, sheet_index)
    result = {"rows": len(rows), "created": 0, "updated": 0, "rejected": []}

    with transaction.atomic():
        for row_number, source_row in enumerate(rows, start=2):
            try:
                with transaction.atomic():
                    row = _mapped_row(source_row)
                    if not any(row.values()):
                        continue
                    if not row["risk"]:
                        raise ValueError("RISQUES est vide.")
                    if not row["impact"]:
                        raise ValueError("IMPACTS est vide.")
                    if not row["recommendation"]:
                        raise ValueError("RECOMMANDATIONS est vide.")
                    ports = parse_port_services(row["port_services"])
                    indicators = parse_indicators(row["indicators"])
                    severity = parse_severity(row["severity"])
                    source_key = _source_key(row, ports, indicators)
                    activity = ActivityCatalog.objects.filter(name__iexact=row["activity"]).first()
                    if not activity:
                        activity = ActivityCatalog.objects.create(name=row["activity"] or "Non classée")
                    elif not activity.is_active:
                        activity.is_active = True
                        activity.save(update_fields=("is_active", "updated_at"))

                    profile, created = RiskProfile.objects.get_or_create(
                        source_key=source_key,
                        defaults={
                            "activity": activity,
                            "name": row["risk"],
                            "impact": row["impact"],
                            "recommendation": row["recommendation"],
                            "default_severity": severity,
                        },
                    )
                    if not created:
                        profile.activity = activity
                        profile.name = row["risk"]
                        profile.impact = row["impact"]
                        profile.recommendation = row["recommendation"]
                        profile.default_severity = severity
                        profile.is_active = True
                        profile.save()

                    profile.port_services.all().delete()
                    RiskProfilePortService.objects.bulk_create([
                        RiskProfilePortService(risk_profile=profile, **item) for item in ports
                    ])
                    profile.indicator_links.all().delete()
                    for name in indicators:
                        indicator = RiskIndicator.objects.filter(name__iexact=name).first()
                        if not indicator:
                            indicator = RiskIndicator.objects.create(name=name)
                        elif not indicator.is_active:
                            indicator.is_active = True
                            indicator.save(update_fields=("is_active", "updated_at"))
                        RiskProfileIndicator.objects.create(risk_profile=profile, indicator=indicator)

                    result["created" if created else "updated"] += 1
            except Exception as exc:
                result["rejected"].append({"row": row_number, "reason": str(exc)})
        if dry_run:
            transaction.set_rollback(True)
    result["dry_run"] = dry_run
    return result
