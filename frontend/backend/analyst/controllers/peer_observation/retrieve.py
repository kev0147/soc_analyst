from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import PeerObservation
from analyst.serializers import PeerObservationSerializer


class PeerObservationRetrieveController(generics.RetrieveAPIView):
    queryset = PeerObservation.objects.select_related("peer_reputation", "network", "network__structure")
    serializer_class = PeerObservationSerializer
    permission_classes = (IsAuthenticated,)
