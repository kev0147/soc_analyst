from rest_framework import serializers

from analyst.models import FlowImport
from analyst.serializers.background_job import BackgroundJobSerializer


class FlowImportSerializer(serializers.ModelSerializer):
    latest_job = serializers.SerializerMethodField()

    class Meta:
        model = FlowImport
        fields = "__all__"
        read_only_fields = (
            "uploaded_by", "uploaded_at", "started_at", "completed_at", "period_start", "period_end",
            "total_rows", "accepted_rows", "inserted_flows", "reused_flows", "rejected_rows", "error_message",
        )

    def get_latest_job(self, obj):
        jobs = list(obj.background_jobs.all())
        job = jobs[0] if jobs else None
        return BackgroundJobSerializer(job).data if job else None
