from rest_framework import serializers

from analyst.models import IPReputation


class IPReputationSerializer(serializers.ModelSerializer):
    results = serializers.SerializerMethodField()

    class Meta:
        model = IPReputation
        fields = "__all__"
        read_only_fields = tuple(field.name for field in IPReputation._meta.fields)

    def get_results(self, obj):
        return [
            {
                "source": result.source,
                "status": result.status,
                "verdict": result.verdict,
                "score": result.score,
                "country": result.country,
                "error_message": result.error_message,
                "analyzed_at": result.analyzed_at,
            }
            for result in obj.results.all()
        ]
