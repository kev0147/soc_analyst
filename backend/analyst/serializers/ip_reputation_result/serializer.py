from rest_framework import serializers

from analyst.models import IPReputationResult


class IPReputationResultSerializer(serializers.ModelSerializer):
    is_stale = serializers.BooleanField(read_only=True)
    freshness_status = serializers.CharField(read_only=True)

    class Meta:
        model = IPReputationResult
        fields = "__all__"
        read_only_fields = tuple(field.name for field in IPReputationResult._meta.fields)
