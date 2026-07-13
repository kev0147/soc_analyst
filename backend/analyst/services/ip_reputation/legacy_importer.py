import csv
import json
import sqlite3
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from analyst.models import IPReputation, IPReputationResult
from analyst.models.choices import ReputationSource, ReputationStatus, ReputationVerdict

from .verdicts import aggregate_verdict, verdict_from_score


SOURCE_ALIASES = {
    "abuse": ReputationSource.ABUSEIPDB,
    "abuseipdb": ReputationSource.ABUSEIPDB,
    "vt": ReputationSource.VIRUSTOTAL,
    "virustotal": ReputationSource.VIRUSTOTAL,
    "shodan": ReputationSource.SHODAN,
}


def _source(value: str) -> str | None:
    normalized = str(value or "").strip().lower()
    return SOURCE_ALIASES.get(normalized)


def _verdict(value: str, score: float | None = None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in ReputationVerdict.values:
        return normalized
    if normalized in {"malveillant", "malicious", "bad"}:
        return ReputationVerdict.MALICIOUS
    if normalized in {"suspect", "suspicious"}:
        return ReputationVerdict.SUSPICIOUS
    if normalized in {"propre", "clean", "ok", "safe"}:
        return ReputationVerdict.CLEAN
    return verdict_from_score(score)


def _score(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pick(row: dict, *names):
    normalized = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in normalized and normalized[name.lower()] not in (None, ""):
            return normalized[name.lower()]
    return ""


def _rows_from_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _rows_from_sqlite(path: Path) -> list[dict]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = []
        tables = [row[0] for row in connection.execute("select name from sqlite_master where type='table'")]
        for table in tables:
            columns = [row[1] for row in connection.execute(f"pragma table_info({table})")]
            if not any(column.lower() in {"ip", "ip_address", "address"} for column in columns):
                continue
            for row in connection.execute(f"select * from {table}"):
                item = dict(row)
                item["_table"] = table
                rows.append(item)
        return rows
    finally:
        connection.close()


@transaction.atomic
def import_legacy_reputation(path: str | Path) -> dict:
    path = Path(path)
    rows = _rows_from_csv(path) if path.suffix.lower() == ".csv" else _rows_from_sqlite(path)
    imported = 0
    skipped = 0
    errors = []
    for index, row in enumerate(rows, start=1):
        try:
            ip = _pick(row, "ip", "ip_address", "address")
            source = _source(_pick(row, "source", "platform", "tool", "_table"))
            if not ip or not source:
                skipped += 1
                continue
            score = _score(_pick(row, "score", "abuseConfidenceScore", "malicious_score", "risk_score"))
            country = str(_pick(row, "country", "countryCode", "country_code") or "").upper()[:2]
            verdict = _verdict(_pick(row, "verdict", "classification", "result", "status"), score)
            analyzed_at = timezone.now()
            reputation, _ = IPReputation.objects.get_or_create(ip_address=ip)
            IPReputationResult.objects.update_or_create(
                reputation=reputation,
                source=source,
                defaults={
                    "status": ReputationStatus.SUCCESS,
                    "verdict": verdict,
                    "score": score,
                    "country": country,
                    "raw": json.loads(json.dumps(row, default=str)),
                    "error_message": "",
                    "analyzed_at": analyzed_at,
                },
            )
            results = list(reputation.results.all())
            reputation.source_count = len(results)
            reputation.successful_source_count = len([item for item in results if item.status == ReputationStatus.SUCCESS])
            reputation.verdict = aggregate_verdict(results)
            reputation.score = max((item.score for item in results if item.score is not None), default=None)
            reputation.country = next((item.country for item in results if item.country), reputation.country)
            reputation.last_analyzed_at = analyzed_at
            reputation.save()
            imported += 1
        except Exception as exc:
            errors.append({"row": index, "reason": str(exc)})
    return {"row_count": len(rows), "imported": imported, "skipped": skipped, "errors": errors}
