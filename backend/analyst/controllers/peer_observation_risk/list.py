from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import PeerObservationRisk
from analyst.serializers import PeerObservationRiskSerializer


class PeerObservationRiskListController(generics.ListAPIView):
    serializer_class = PeerObservationRiskSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = PeerObservationRisk.objects.select_related("peer_observation", "risk_profile")
        peer_observation_id = self.request.query_params.get("peer_observation_id")
        risk_profile_id = self.request.query_params.get("risk_profile_id")
        if peer_observation_id:
            queryset = queryset.filter(peer_observation_id=peer_observation_id)
        if risk_profile_id:
            queryset = queryset.filter(risk_profile_id=risk_profile_id)
        return queryset
