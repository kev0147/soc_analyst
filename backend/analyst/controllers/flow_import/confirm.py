from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import FlowImport
from analyst.models.choices import BackgroundJobKind, BackgroundJobStatus, ImportStatus
from analyst.serializers import BackgroundJobSerializer, FlowImportSerializer
from analyst.services.jobs import enqueue_background_job


class FlowImportConfirmInputSerializer(serializers.Serializer):
    import_id = serializers.IntegerField()


class FlowImportConfirmController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = FlowImportConfirmInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        flow_import = get_object_or_404(FlowImport, pk=serializer.validated_data["import_id"])
        active_job = flow_import.background_jobs.filter(
            status__in=(BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING)
        ).first()
        if flow_import.status != ImportStatus.PENDING and not active_job:
            return Response(
                {"detail": "Seul un import en attente peut être confirmé."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        job, created = enqueue_background_job(
            kind=BackgroundJobKind.FLOW_IMPORT,
            payload={"import_id": flow_import.id},
            user=request.user,
            flow_import=flow_import,
        )

        record_audit(
            request,
            "FLOW_IMPORT_CONFIRMED",
            flow_import,
            details={
                "job_id": str(job.id),
                "job_created": created,
                "job_status": job.status,
            },
        )
        return Response(
            {
                "job": BackgroundJobSerializer(job).data,
                "flow_import": FlowImportSerializer(flow_import).data,
                "already_queued": not created,
            },
            status=status.HTTP_202_ACCEPTED,
        )
