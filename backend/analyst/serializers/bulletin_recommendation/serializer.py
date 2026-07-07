from rest_framework import serializers

from analyst.models import BulletinRecommendation


class BulletinRecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinRecommendation
        fields = "__all__"

