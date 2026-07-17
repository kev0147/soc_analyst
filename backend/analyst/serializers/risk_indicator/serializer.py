from rest_framework import serializers

from analyst.models import RiskIndicator


class RiskIndicatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskIndicator
        fields = "__all__"
