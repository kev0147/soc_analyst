from rest_framework import serializers

from analyst.models import FlowImport


class FlowImportSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlowImport
        fields = "__all__"
        read_only_fields = (
            "uploaded_by", "uploaded_at", "started_at", "completed_at", "period_start", "period_end",
            "total_rows", "accepted_rows", "inserted_flows", "reused_flows", "rejected_rows", "error_message",
        )

