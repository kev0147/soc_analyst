from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import FlowImport
from analyst.serializers import FlowImportSerializer


class FlowImportCreateController(AuditedCreateController):
    queryset = FlowImport.objects.all()
    serializer_class = FlowImportSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "IMPORT_CREATED"
