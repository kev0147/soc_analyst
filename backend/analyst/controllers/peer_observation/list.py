from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import PeerObservation
from analyst.serializers import PeerObservationSerializer
from .filters import apply_peer_observation_filters, apply_peer_observation_ordering


class PeerObservationListController(generics.ListAPIView):
    serializer_class = PeerObservationSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = PeerObservation.objects.select_related("peer_reputation", "network", "network__structure")
        queryset = apply_peer_observation_filters(queryset, self.request.query_params)
        return apply_peer_observation_ordering(queryset, self.request.query_params)
