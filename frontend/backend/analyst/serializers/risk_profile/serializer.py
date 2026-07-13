from rest_framework import serializers

from analyst.models import RiskProfile


class RiskProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskProfile
        fields = "__all__"
