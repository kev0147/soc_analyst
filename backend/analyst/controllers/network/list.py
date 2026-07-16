from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Network
from analyst.serializers import NetworkSerializer


class NetworkListController(generics.ListAPIView):
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = super().get_queryset()
        structure_id = self.request.query_params.get("structure_id")
        if structure_id:
            queryset = queryset.filter(structure_id=structure_id)
        is_active = self.request.query_params.get("is_active")
        if is_active not in (None, ""):
            queryset = queryset.filter(is_active=is_active.lower() in {"1", "true", "yes"})
        return queryset
