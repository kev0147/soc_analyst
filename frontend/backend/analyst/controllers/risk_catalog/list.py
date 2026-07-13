from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import RiskCatalog
from analyst.serializers import RiskCatalogSerializer


class RiskCatalogListController(generics.ListAPIView):
    queryset = RiskCatalog.objects.all()
    serializer_class = RiskCatalogSerializer
    permission_classes = (IsAuthenticated,)
