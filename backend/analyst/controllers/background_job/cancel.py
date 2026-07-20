from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BackgroundJob
from analyst.models.choices import BackgroundJobStatus, UserRole
from analyst.serializers import BackgroundJobSerializer


class BackgroundJobCancelController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    @transaction.atomic
    def post(self, request, pk):
        job = get_object_or_404(BackgroundJob.objects.select_for_update(), pk=pk)
        if request.user.role != UserRole.ADMIN and job.created_by_id != request.user.id:
            return Response({"detail": "Tu ne peux arrêter que tes propres tâches."}, status=status.HTTP_403_FORBIDDEN)
        if job.status not in (BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING):
            return Response({"detail": "Cette tâche est déjà terminée."}, status=status.HTTP_400_BAD_REQUEST)

        now = timezone.now()
        job.cancel_requested_at = now
        job.status_message = "Arrêt demandé"
        update_fields = ["cancel_requested_at", "status_message", "updated_at"]
        if job.status == BackgroundJobStatus.QUEUED:
            job.status = BackgroundJobStatus.CANCELED
            job.completed_at = now
            update_fields.extend(("status", "completed_at"))
        job.save(update_fields=update_fields)
        record_audit(request, "BACKGROUND_JOB_CANCEL_REQUESTED", job)
        return Response(BackgroundJobSerializer(job).data, status=status.HTTP_202_ACCEPTED)
