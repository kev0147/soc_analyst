from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RiskProfile
from analyst.serializers import RiskProfileSerializer


class RiskProfileCreateController(AuditedCreateController):
    queryset = RiskProfile.objects.all()
    serializer_class = RiskProfileSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RISK_PROFILE_CREATED"
