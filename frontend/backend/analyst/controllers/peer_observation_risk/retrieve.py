from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import PeerObservationRisk
from analyst.serializers import PeerObservationRiskSerializer


class PeerObservationRiskRetrieveController(generics.RetrieveAPIView):
    queryset = PeerObservationRisk.objects.select_related("peer_observation", "risk_profile")
    serializer_class = PeerObservationRiskSerializer
    permission_classes = (IsAuthenticated,)
