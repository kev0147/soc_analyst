from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import DetectionHit
from analyst.serializers import DetectionHitSerializer


class DetectionHitRetrieveController(generics.RetrieveAPIView):
    serializer_class = DetectionHitSerializer
    permission_classes = (IsAuthenticated,)
    queryset = DetectionHit.objects.select_related("rule", "structure", "network")
