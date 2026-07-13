from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinFinding
from analyst.serializers import BulletinFindingSerializer


class BulletinFindingListController(generics.ListAPIView):
    serializer_class = BulletinFindingSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = BulletinFinding.objects.select_related(
            "bulletin",
            "peer_observation",
            "peer_observation__peer_reputation",
            "risk_profile",
        )
        bulletin_id = self.request.query_params.get("bulletin_id")
        peer_observation_id = self.request.query_params.get("peer_observation_id")
        risk_profile_id = self.request.query_params.get("risk_profile_id")
        if bulletin_id:
            queryset = queryset.filter(bulletin_id=bulletin_id)
        if peer_observation_id:
            queryset = queryset.filter(peer_observation_id=peer_observation_id)
        if risk_profile_id:
            queryset = queryset.filter(risk_profile_id=risk_profile_id)
        return queryset
