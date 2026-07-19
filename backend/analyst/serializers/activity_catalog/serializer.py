from rest_framework import serializers

from analyst.models import ActivityCatalog


class ActivityCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityCatalog
        fields = "__all__"
