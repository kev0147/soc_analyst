from rest_framework import serializers

from analyst.models import IPReputation
from analyst.models.choices import ReputationSource


REPUTATION_SOURCES = (ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL)


class IPReputationSerializer(serializers.ModelSerializer):
    results = serializers.SerializerMethodField()
    freshness_status = serializers.SerializerMethodField()
    next_refresh_at = serializers.SerializerMethodField()

    class Meta:
        model = IPReputation
        fields = "__all__"
        read_only_fields = tuple(field.name for field in IPReputation._meta.fields)

    def get_results(self, obj):
        current = {result.source: result for result in obj.results.all() if result.source in REPUTATION_SOURCES}
        rows = []
        for source in REPUTATION_SOURCES:
            result = current.get(source)
            if result is None:
                rows.append({
                    "source": source,
                    "status": "never_analyzed",
                    "verdict": "unknown",
                    "score": None,
                    "country": "",
                    "error_message": "",
                    "analyzed_at": None,
                    "expires_at": None,
                    "is_stale": True,
                    "freshness_status": "never_analyzed",
                })
                continue
            rows.append({
                "source": result.source,
                "status": result.status,
                "verdict": result.verdict,
                "score": result.score,
                "country": result.country,
                "error_message": result.error_message,
                "analyzed_at": result.analyzed_at,
                "expires_at": result.expires_at,
                "is_stale": result.is_stale,
                "freshness_status": result.freshness_status,
            })
        return rows

    def get_freshness_status(self, obj):
        rows = self.get_results(obj)
        if all(row["freshness_status"] == "never_analyzed" for row in rows):
            return "never_analyzed"
        if any(row["freshness_status"] == "never_analyzed" for row in rows):
            return "incomplete"
        if any(row["is_stale"] for row in rows):
            return "stale"
        if any(row["freshness_status"] in {"error", "unavailable"} for row in rows):
            return "incomplete"
        return "fresh"

    def get_next_refresh_at(self, obj):
        dates = [
            result.expires_at
            for result in obj.results.all()
            if result.source in REPUTATION_SOURCES and result.expires_at is not None
        ]
        return min(dates) if dates else None
