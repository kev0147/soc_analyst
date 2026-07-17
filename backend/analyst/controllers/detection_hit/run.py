from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models.choices import BackgroundJobKind
from analyst.serializers import BackgroundJobSerializer
from analyst.services.jobs import enqueue_background_job


class DetectionRunInputSerializer(serializers.Serializer):
    scope = serializers.ChoiceField(
        choices=("all_flows", "structure", "import", "date_range"),
        default="structure",
    )
    structure_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    import_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    date_from = serializers.DateTimeField(required=False, allow_null=True)
    date_to = serializers.DateTimeField(required=False, allow_null=True)
    rule_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_empty=False,
    )

    def validate(self, attrs):
        scope = attrs["scope"]
        if scope == "structure" and not attrs.get("structure_id"):
            raise serializers.ValidationError({"structure_id": "Ce champ est obligatoire."})
        if scope == "import" and not attrs.get("import_id"):
            raise serializers.ValidationError({"import_id": "Ce champ est obligatoire."})
        if scope == "date_range" and (not attrs.get("date_from") or not attrs.get("date_to")):
            raise serializers.ValidationError({"date_range": "Les deux dates sont obligatoires."})
        if attrs.get("date_from") and attrs.get("date_to") and attrs["date_to"] < attrs["date_from"]:
            raise serializers.ValidationError({"date_to": "Doit être postérieure à date_from."})
        return attrs


class DetectionRunController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = DetectionRunInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        payload = {
            "scope": data["scope"],
            "structure_id": data.get("structure_id"),
            "import_id": data.get("import_id"),
            "date_from": data.get("date_from").isoformat() if data.get("date_from") else None,
            "date_to": data.get("date_to").isoformat() if data.get("date_to") else None,
            "rule_ids": data.get("rule_ids") or [],
        }
        job, created = enqueue_background_job(
            kind=BackgroundJobKind.DETECTION,
            payload=payload,
            user=request.user,
        )
        record_audit(request, "DETECTION_RUN_REQUESTED", details={**payload, "job_id": str(job.id)})
        return Response(
            {"job": BackgroundJobSerializer(job).data, "already_queued": not created},
            status=status.HTTP_202_ACCEPTED,
        )
