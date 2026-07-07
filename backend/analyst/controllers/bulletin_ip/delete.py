from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinIP


class BulletinIPDeleteController(AuditedDestroyController):
    queryset = BulletinIP.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_IP_DELETED"
