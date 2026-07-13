from rest_framework import serializers

from analyst.models import BulletinResponse


class BulletinResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinResponse
        fields = "__all__"
        read_only_fields = ("created_by", "created_at", "updated_at")

