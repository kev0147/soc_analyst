from rest_framework import serializers

from analyst.models import RiskCatalog


class RiskCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskCatalog
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

