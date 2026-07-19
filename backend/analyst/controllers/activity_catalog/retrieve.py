from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import ActivityCatalog
from analyst.serializers import ActivityCatalogSerializer


class ActivityCatalogRetrieveController(generics.RetrieveAPIView):
    queryset = ActivityCatalog.objects.all()
    serializer_class = ActivityCatalogSerializer
    permission_classes = (IsAuthenticated,)
