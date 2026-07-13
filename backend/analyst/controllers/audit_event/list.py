from rest_framework import generics
from analyst.controllers.permissions import IsAdmin

from analyst.models import AuditEvent
from analyst.serializers import AuditEventSerializer
from analyst.controllers.audit import record_audit


class AuditEventListController(generics.ListAPIView):
    queryset = AuditEvent.objects.all()
    serializer_class = AuditEventSerializer
    permission_classes = (IsAdmin,)

    def get_queryset(self):
        queryset = super().get_queryset()
        action = self.request.query_params.get("action")
        if action:
            queryset = queryset.filter(action=action)
        actor_id = self.request.query_params.get("actor_id")
        if actor_id:
            queryset = queryset.filter(actor_id=actor_id)
        entity_type = self.request.query_params.get("entity_type")
        if entity_type:
            queryset = queryset.filter(entity_type=entity_type)
        return queryset

    def list(self, request, *args, **kwargs):
        record_audit(request, "AUDIT_EVENTS_VIEWED", details={"view": "list"})
        return super().list(request, *args, **kwargs)
