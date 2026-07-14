from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BackgroundJob
from analyst.serializers import BackgroundJobSerializer
from analyst.services.jobs import retry_background_job


class BackgroundJobRetryController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request, pk):
        job = get_object_or_404(BackgroundJob, pk=pk)
        try:
            retried = retry_background_job(job, request.user)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        record_audit(
            request,
            "BACKGROUND_JOB_RETRIED",
            retried,
            details={"retried_from": str(job.id), "job_kind": job.kind},
        )
        return Response(BackgroundJobSerializer(retried).data, status=status.HTTP_202_ACCEPTED)
