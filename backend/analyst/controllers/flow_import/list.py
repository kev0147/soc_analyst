from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import FlowImport
from analyst.serializers import FlowImportSerializer


class FlowImportListController(generics.ListAPIView):
    queryset = FlowImport.objects.prefetch_related("background_jobs")
    serializer_class = FlowImportSerializer
    permission_classes = (IsAuthenticated,)
