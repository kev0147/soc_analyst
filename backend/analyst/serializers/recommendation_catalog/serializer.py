from rest_framework import serializers

from analyst.models import RecommendationCatalog


class RecommendationCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecommendationCatalog
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

