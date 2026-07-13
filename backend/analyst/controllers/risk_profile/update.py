from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskProfile
from analyst.serializers import RiskProfileSerializer


class RiskProfileUpdateController(AuditedUpdateController):
    queryset = RiskProfile.objects.all()
    serializer_class = RiskProfileSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_PROFILE_UPDATED"
