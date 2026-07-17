from rest_framework import serializers

from analyst.models import RiskProfile
from analyst.serializers.risk_indicator import RiskIndicatorSerializer
from analyst.serializers.risk_profile_port_service import RiskProfilePortServiceSerializer


class RiskProfileSerializer(serializers.ModelSerializer):
    indicators = serializers.SerializerMethodField()
    port_services = RiskProfilePortServiceSerializer(many=True, read_only=True)

    class Meta:
        model = RiskProfile
        fields = "__all__"

    def get_indicators(self, obj):
        indicators = [link.indicator for link in obj.indicator_links.all()]
        return RiskIndicatorSerializer(indicators, many=True).data
