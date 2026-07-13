from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinRisk
from analyst.serializers import BulletinRiskSerializer


class BulletinRiskCreateController(AuditedCreateController):
    queryset = BulletinRisk.objects.all()
    serializer_class = BulletinRiskSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RISK_CREATED"
