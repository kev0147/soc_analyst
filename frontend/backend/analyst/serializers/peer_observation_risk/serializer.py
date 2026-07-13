from rest_framework import serializers

from analyst.models import PeerObservationRisk


class PeerObservationRiskSerializer(serializers.ModelSerializer):
    risk_name = serializers.CharField(source="risk_profile.name", read_only=True)
    impact = serializers.CharField(source="risk_profile.impact", read_only=True)
    recommendation = serializers.CharField(source="risk_profile.recommendation", read_only=True)

    class Meta:
        model = PeerObservationRisk
        fields = "__all__"
