from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Structure
from analyst.serializers import StructureSerializer


class StructureRetrieveController(generics.RetrieveAPIView):
    queryset = Structure.objects.all()
    serializer_class = StructureSerializer
    permission_classes = (IsAuthenticated,)
