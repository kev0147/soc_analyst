from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinFinding
from analyst.serializers import BulletinFindingSerializer


class BulletinFindingRetrieveController(generics.RetrieveAPIView):
    queryset = BulletinFinding.objects.select_related(
        "bulletin",
        "peer_observation",
        "peer_observation__peer_reputation",
        "risk_profile",
    )
    serializer_class = BulletinFindingSerializer
    permission_classes = (IsAuthenticated,)
