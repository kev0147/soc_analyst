from rest_framework import serializers

from analyst.models import BulletinTypeCatalog


class BulletinTypeCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinTypeCatalog
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

