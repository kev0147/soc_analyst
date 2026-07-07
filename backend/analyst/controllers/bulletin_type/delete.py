from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinType


class BulletinTypeDeleteController(AuditedDestroyController):
    queryset = BulletinType.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_TYPE_DELETED"
