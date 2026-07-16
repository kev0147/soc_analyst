from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Structure
from analyst.serializers import StructureSerializer


class StructureListController(generics.ListAPIView):
    queryset = Structure.objects.all()
    serializer_class = StructureSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = super().get_queryset()
        is_active = self.request.query_params.get("is_active")
        if is_active not in (None, ""):
            queryset = queryset.filter(is_active=is_active.lower() in {"1", "true", "yes"})
        return queryset
