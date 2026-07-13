from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Flow
from analyst.serializers import FlowSerializer
from analyst.services.flows import apply_flow_filters


class FlowListController(generics.ListAPIView):
    queryset = Flow.objects.all()
    serializer_class = FlowSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return apply_flow_filters(super().get_queryset(), self.request.query_params)
