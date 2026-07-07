from rest_framework import serializers

from analyst.models import BulletinRisk


class BulletinRiskSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinRisk
        fields = "__all__"

