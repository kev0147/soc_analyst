from django.db import transaction
from rest_framework import generics

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Flow, FlowImport


class FlowImportDeleteController(generics.DestroyAPIView):
    queryset = FlowImport.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "IMPORT_DELETED"

    def perform_destroy(self, instance):
        with transaction.atomic():
            flow_ids = list(instance.items.values_list("flow_id", flat=True))
            record_audit(self.request, self.audit_action, instance, {"flow_links": len(flow_ids)})
            instance.delete()
            Flow.objects.filter(pk__in=flow_ids, import_items__isnull=True).delete()
