from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BackgroundJob
from analyst.serializers import BackgroundJobSerializer


class BackgroundJobListController(generics.ListAPIView):
    serializer_class = BackgroundJobSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = BackgroundJob.objects.select_related("created_by", "flow_import")
        status = self.request.query_params.get("status")
        kind = self.request.query_params.get("kind")
        flow_import_id = self.request.query_params.get("flow_import_id")
        if status:
            queryset = queryset.filter(status=status)
        if kind:
            queryset = queryset.filter(kind=kind)
        if flow_import_id:
            queryset = queryset.filter(flow_import_id=flow_import_id)
        return queryset
