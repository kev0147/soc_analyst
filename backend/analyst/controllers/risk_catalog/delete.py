from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskCatalog


class RiskCatalogDeleteController(DeactivateController):
    queryset = RiskCatalog.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_DISABLED"
