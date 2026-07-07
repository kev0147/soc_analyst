from rest_framework import serializers

from analyst.models import Network


class NetworkSerializer(serializers.ModelSerializer):
    class Meta:
        model = Network
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

