from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models.choices import ReputationSource
from analyst.services.ip_reputation import run_reputation_analysis


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
        try:
            result = run_reputation_analysis(
                scope=data["scope"],
                import_id=data.get("import_id"),
                tools=data.get("tools"),
                limit=data.get("limit") or 50,
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        record_audit(
            request,
            "IP_REPUTATION_ANALYSIS_RUN",
            details={
                "scope": result["scope"],
                "import_id": result["import_id"],
                "tools": result["tools"],
                "candidate_count": result["candidate_count"],
                "analyzed_count": result["analyzed_count"],
            },
        )
        return Response(result, status=status.HTTP_202_ACCEPTED)
