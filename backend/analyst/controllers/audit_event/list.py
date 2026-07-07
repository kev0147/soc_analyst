from rest_framework import generics
from analyst.controllers.permissions import IsAdmin

from analyst.models import AuditEvent
from analyst.serializers import AuditEventSerializer


class AuditEventListController(generics.ListAPIView):
    queryset = AuditEvent.objects.all()
    serializer_class = AuditEventSerializer
    permission_classes = (IsAdmin,)
