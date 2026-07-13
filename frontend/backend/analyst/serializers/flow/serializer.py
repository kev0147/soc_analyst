from rest_framework import serializers

from analyst.models import Flow


class FlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = Flow
        fields = "__all__"
        read_only_fields = ("conversation_ip_a", "conversation_ip_b", "created_at")

    def validate_src_port(self, value):
        if value is not None and value > 65535:
            raise serializers.ValidationError("Le port doit être compris entre 0 et 65535.")
        return value

    def validate_dst_port(self, value):
        if value is not None and value > 65535:
            raise serializers.ValidationError("Le port doit être compris entre 0 et 65535.")
        return value

