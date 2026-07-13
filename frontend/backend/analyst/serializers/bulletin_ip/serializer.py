from rest_framework import serializers

from analyst.models import BulletinIP


class BulletinIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinIP
        fields = "__all__"

