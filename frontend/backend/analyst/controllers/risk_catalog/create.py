from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskCatalog
from analyst.serializers import RiskCatalogSerializer


class RiskCatalogCreateController(AuditedCreateController):
    queryset = RiskCatalog.objects.all()
    serializer_class = RiskCatalogSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_CREATED"
