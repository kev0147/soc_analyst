from rest_framework import serializers

from analyst.models import DetectionRule
from analyst.models.choices import DetectionRuleType


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = "__all__"

    def validate_parameters(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Les paramètres doivent être un objet JSON.")
        rule_type = self.initial_data.get("rule_type") or getattr(self.instance, "rule_type", None)
        numeric_parameters = {
            DetectionRuleType.LONG_SSH: ("min_duration_seconds",),
            DetectionRuleType.MALICIOUS_HIGH_VOLUME: ("min_total_bytes",),
            DetectionRuleType.REPEATED_PEER: ("min_flow_count",),
            DetectionRuleType.SENSITIVE_PORT: ("min_flow_count",),
            DetectionRuleType.MULTI_HOST_PEER: ("min_host_count",),
        }.get(rule_type, ())
        for name in numeric_parameters:
            if name in value:
                try:
                    parsed = int(value[name])
                except (TypeError, ValueError) as exc:
                    raise serializers.ValidationError({name: "Doit être un entier."}) from exc
                if parsed < 1:
                    raise serializers.ValidationError({name: "Doit être supérieur à zéro."})
        if "ports" in value:
            if not isinstance(value["ports"], list):
                raise serializers.ValidationError({"ports": "Doit être une liste."})
            for port in value["ports"]:
                try:
                    parsed = int(port)
                except (TypeError, ValueError) as exc:
                    raise serializers.ValidationError({"ports": "Chaque port doit être un entier."}) from exc
                if parsed < 0 or parsed > 65535:
                    raise serializers.ValidationError({"ports": "Chaque port doit être compris entre 0 et 65535."})
        return value
