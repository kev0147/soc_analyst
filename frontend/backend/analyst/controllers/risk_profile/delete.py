from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskProfile


class RiskProfileDeleteController(DeactivateController):
    queryset = RiskProfile.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_PROFILE_DISABLED"
