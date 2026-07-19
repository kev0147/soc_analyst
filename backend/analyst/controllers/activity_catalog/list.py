from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import ActivityCatalog
from analyst.serializers import ActivityCatalogSerializer


class ActivityCatalogListController(generics.ListAPIView):
    serializer_class = ActivityCatalogSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = ActivityCatalog.objects.all()
        is_active = self.request.query_params.get("is_active")
        if is_active in ("true", "false"):
            queryset = queryset.filter(is_active=is_active == "true")
        return queryset
