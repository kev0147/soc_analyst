from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Flow
from analyst.serializers import FlowSerializer


class FlowListController(generics.ListAPIView):
    queryset = Flow.objects.all()
    serializer_class = FlowSerializer
    permission_classes = (IsAuthenticated,)
