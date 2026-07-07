from rest_framework import serializers

from analyst.models import AuditEvent


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = "__all__"
        read_only_fields = tuple(field.name for field in AuditEvent._meta.fields)

