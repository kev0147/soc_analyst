from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models.choices import BackgroundJobKind, ReputationSource
from analyst.serializers import BackgroundJobSerializer
from analyst.services.jobs import enqueue_background_job


class IPAnalysisRunInputSerializer(serializers.Serializer):
    scope = serializers.ChoiceField(choices=("all_flows", "import"), default="all_flows")
    import_id = serializers.IntegerField(required=False, allow_null=True)
    tools = serializers.ListField(
        child=serializers.ChoiceField(choices=ReputationSource.choices),
        required=False,
        allow_empty=False,
    )
    limit = serializers.IntegerField(required=False, min_value=1, max_value=500, default=50)


class IPAnalysisRunController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = IPAnalysisRunInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data["scope"] == "import" and not data.get("import_id"):
            return Response(
                {"import_id": ["Ce champ est obligatoire lorsque scope=import."]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        payload = {
            "scope": data["scope"],
            "import_id": data.get("import_id"),
            "tools": data.get("tools"),
            "limit": data.get("limit") or 50,
        }
        job, created = enqueue_background_job(
            kind=BackgroundJobKind.IP_REPUTATION,
            payload=payload,
            user=request.user,
        )
        record_audit(
            request,
            "IP_REPUTATION_ANALYSIS_RUN",
            details={
                **payload,
                "job_id": str(job.id),
                "job_created": created,
            },
        )
        return Response(
            {"job": BackgroundJobSerializer(job).data, "already_queued": not created},
            status=status.HTTP_202_ACCEPTED,
        )
