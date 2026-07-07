from rest_framework import serializers

from analyst.models import BulletinType


class BulletinTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinType
        fields = "__all__"

