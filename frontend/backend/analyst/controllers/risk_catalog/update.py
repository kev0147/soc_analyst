from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskCatalog
from analyst.serializers import RiskCatalogSerializer


class RiskCatalogUpdateController(AuditedUpdateController):
    queryset = RiskCatalog.objects.all()
    serializer_class = RiskCatalogSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_UPDATED"
