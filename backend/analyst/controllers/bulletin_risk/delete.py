from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinRisk


class BulletinRiskDeleteController(AuditedDestroyController):
    queryset = BulletinRisk.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RISK_DELETED"
