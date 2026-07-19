from rest_framework import serializers

from analyst.models import BulletinActivity


class BulletinActivitySerializer(serializers.ModelSerializer):
    activity_name = serializers.CharField(source="activity.name", read_only=True)

    class Meta:
        model = BulletinActivity
        fields = "__all__"
