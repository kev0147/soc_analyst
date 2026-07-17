from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models.choices import BackgroundJobKind
from analyst.serializers import BackgroundJobSerializer
from analyst.services.jobs import enqueue_background_job


class DailyFlowAggregateRunInputSerializer(serializers.Serializer):
    date_from = serializers.DateField()
    date_to = serializers.DateField()
    structure_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)

    def validate(self, attrs):
        if attrs["date_to"] < attrs["date_from"]:
            raise serializers.ValidationError({"date_to": "Doit être postérieure ou égale à date_from."})
        if (attrs["date_to"] - attrs["date_from"]).days >= 366:
            raise serializers.ValidationError({"date_to": "La période est limitée à 366 jours."})
        return attrs


class DailyFlowAggregateRunController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = DailyFlowAggregateRunInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        payload = {
            "date_from": data["date_from"].isoformat(),
            "date_to": data["date_to"].isoformat(),
            "structure_id": data.get("structure_id"),
        }
        job, created = enqueue_background_job(
            kind=BackgroundJobKind.DAILY_AGGREGATION,
            payload=payload,
            user=request.user,
        )
        record_audit(request, "DAILY_FLOW_AGGREGATION_REQUESTED", details={**payload, "job_id": str(job.id)})
        return Response(
            {"job": BackgroundJobSerializer(job).data, "already_queued": not created},
            status=status.HTTP_202_ACCEPTED,
        )
