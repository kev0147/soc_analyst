from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import FlowImportItem
from analyst.serializers import FlowImportItemSerializer


class FlowImportItemListController(generics.ListAPIView):
    queryset = FlowImportItem.objects.all()
    serializer_class = FlowImportItemSerializer
    permission_classes = (IsAuthenticated,)
