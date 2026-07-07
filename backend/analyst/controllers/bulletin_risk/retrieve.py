from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinRisk
from analyst.serializers import BulletinRiskSerializer


class BulletinRiskRetrieveController(generics.RetrieveAPIView):
    queryset = BulletinRisk.objects.all()
    serializer_class = BulletinRiskSerializer
    permission_classes = (IsAuthenticated,)
