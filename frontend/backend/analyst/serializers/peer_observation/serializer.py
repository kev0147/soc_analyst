from rest_framework import serializers

from analyst.models import PeerObservation


class PeerObservationSerializer(serializers.ModelSerializer):
    peer_ip = serializers.CharField(read_only=True)
    peer_country = serializers.CharField(read_only=True)
    reputation_verdict = serializers.CharField(source="peer_reputation.verdict", read_only=True)
    reputation_score = serializers.FloatField(source="peer_reputation.score", read_only=True)

    class Meta:
        model = PeerObservation
        fields = "__all__"
