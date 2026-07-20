from rest_framework import serializers

from analyst.models import PeerObservation


class PeerObservationSerializer(serializers.ModelSerializer):
    peer_ip = serializers.CharField(read_only=True)
    peer_country = serializers.SerializerMethodField()
    network_name = serializers.CharField(source="network.name", read_only=True)
    structure_id = serializers.IntegerField(source="network.structure_id", read_only=True)
    structure_code = serializers.CharField(source="network.structure.code", read_only=True)
    reputation_verdict = serializers.CharField(source="peer_reputation.verdict", read_only=True)
    reputation_score = serializers.FloatField(source="peer_reputation.score", read_only=True)
    reputation_results = serializers.SerializerMethodField()

    class Meta:
        model = PeerObservation
        fields = "__all__"

    def get_peer_country(self, obj):
        return obj.peer_country

    def get_reputation_results(self, obj):
        return [
            {
                "source": result.source,
                "status": result.status,
                "verdict": result.verdict,
                "score": result.score,
                "country": result.country,
                "analyzed_at": result.analyzed_at,
            }
            for result in obj.peer_reputation.results.all()
        ]
