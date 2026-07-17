from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import DetectionRule
from analyst.serializers import DetectionRuleSerializer


class DetectionRuleRetrieveController(generics.RetrieveAPIView):
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
    permission_classes = (IsAuthenticated,)
