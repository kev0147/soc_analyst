from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BackgroundJob
from analyst.serializers import BackgroundJobSerializer


class BackgroundJobRetrieveController(generics.RetrieveAPIView):
    queryset = BackgroundJob.objects.select_related("created_by", "flow_import")
    serializer_class = BackgroundJobSerializer
    permission_classes = (IsAuthenticated,)
