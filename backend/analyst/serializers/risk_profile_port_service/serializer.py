from rest_framework import serializers

from analyst.models import RiskProfilePortService


class RiskProfilePortServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskProfilePortService
        fields = ("id", "port", "service")
