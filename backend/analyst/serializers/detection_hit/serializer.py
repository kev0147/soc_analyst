from rest_framework import serializers

from analyst.models import DetectionHit


class DetectionHitSerializer(serializers.ModelSerializer):
    rule_code = serializers.CharField(source="rule.code", read_only=True)
    rule_name = serializers.CharField(source="rule.name", read_only=True)
    structure_code = serializers.CharField(source="structure.code", read_only=True)
    structure_name = serializers.CharField(source="structure.name", read_only=True)
    network_name = serializers.CharField(source="network.name", read_only=True, allow_null=True)

    class Meta:
        model = DetectionHit
        fields = "__all__"
        read_only_fields = tuple(field.name for field in DetectionHit._meta.fields)
