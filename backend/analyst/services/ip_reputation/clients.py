import json
import urllib.parse
import urllib.request
from dataclasses import dataclass

from django.conf import settings
from django.utils import timezone

from analyst.models.choices import ReputationSource, ReputationStatus, ReputationVerdict

from .verdicts import verdict_from_score


@dataclass(frozen=True)
class ReputationClientResult:
    source: str
    status: str
    verdict: str
    score: float | None
    country: str
    raw: dict
    error_message: str
    analyzed_at: object


def _now_result(source: str, status: str, verdict: str, score=None, country="", raw=None, error_message=""):
    return ReputationClientResult(
        source=source,
        status=status,
        verdict=verdict,
        score=score,
        country=country or "",
        raw=raw or {},
        error_message=error_message,
        analyzed_at=timezone.now(),
    )


def _get_json(url: str, headers: dict | None = None) -> dict:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(request, timeout=settings.IP_REPUTATION_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


class AbuseIPDBClient:
    source = ReputationSource.ABUSEIPDB

    def analyze(self, ip: str) -> ReputationClientResult:
        key = settings.ABUSEIPDB_API_KEY
        if not key:
            return _now_result(self.source, ReputationStatus.SKIPPED, ReputationVerdict.UNKNOWN, error_message="ABUSEIPDB_API_KEY manquante.")
        try:
            query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
            raw = _get_json(
                f"https://api.abuseipdb.com/api/v2/check?{query}",
                headers={"Key": key, "Accept": "application/json"},
            )
            data = raw.get("data", {})
            score = float(data.get("abuseConfidenceScore") or 0)
            return _now_result(
                self.source,
                ReputationStatus.SUCCESS,
                verdict_from_score(score),
                score=score,
                country=(data.get("countryCode") or "").upper(),
                raw=raw,
            )
        except Exception as exc:
            return _now_result(self.source, ReputationStatus.ERROR, ReputationVerdict.UNKNOWN, error_message=str(exc))


class VirusTotalClient:
    source = ReputationSource.VIRUSTOTAL

    def analyze(self, ip: str) -> ReputationClientResult:
        key = settings.VIRUSTOTAL_API_KEY
        if not key:
            return _now_result(self.source, ReputationStatus.SKIPPED, ReputationVerdict.UNKNOWN, error_message="VIRUSTOTAL_API_KEY manquante.")
        try:
            raw = _get_json(
                f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}",
                headers={"x-apikey": key, "Accept": "application/json"},
            )
            attributes = raw.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            total = max(malicious + suspicious + harmless + int(stats.get("undetected") or 0), 1)
            score = ((malicious * 100) + (suspicious * 50)) / total
            return _now_result(
                self.source,
                ReputationStatus.SUCCESS,
                verdict_from_score(score),
                score=round(score, 2),
                country=(attributes.get("country") or "").upper(),
                raw=raw,
            )
        except Exception as exc:
            return _now_result(self.source, ReputationStatus.ERROR, ReputationVerdict.UNKNOWN, error_message=str(exc))


CLIENTS = {
    ReputationSource.ABUSEIPDB: AbuseIPDBClient,
    ReputationSource.VIRUSTOTAL: VirusTotalClient,
}
