from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import FlowImport
from analyst.serializers import FlowImportSerializer


class FlowImportRetrieveController(generics.RetrieveAPIView):
    queryset = FlowImport.objects.all()
    serializer_class = FlowImportSerializer
    permission_classes = (IsAuthenticated,)
