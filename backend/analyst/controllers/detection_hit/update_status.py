from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import DetectionHit
from analyst.models.choices import DetectionHitStatus
from analyst.serializers import DetectionHitSerializer


class DetectionHitStatusInputSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=DetectionHitStatus.choices)


class DetectionHitStatusController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request, pk):
        serializer = DetectionHitStatusInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        hit = get_object_or_404(
            DetectionHit.objects.select_related("rule", "structure", "network"),
            pk=pk,
        )
        hit.status = serializer.validated_data["status"]
        hit.save(update_fields=("status", "updated_at"))
        record_audit(request, "DETECTION_HIT_STATUS_UPDATED", hit, details={"status": hit.status})
        return Response(DetectionHitSerializer(hit).data)
