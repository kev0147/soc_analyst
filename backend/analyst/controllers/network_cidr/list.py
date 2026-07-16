from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import NetworkCIDR
from analyst.serializers import NetworkCIDRSerializer


class NetworkCIDRListController(generics.ListAPIView):
    queryset = NetworkCIDR.objects.all()
    serializer_class = NetworkCIDRSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = super().get_queryset()
        network_id = self.request.query_params.get("network_id")
        if network_id:
            queryset = queryset.filter(network_id=network_id)
        structure_id = self.request.query_params.get("structure_id")
        if structure_id:
            queryset = queryset.filter(network__structure_id=structure_id)
        return queryset
