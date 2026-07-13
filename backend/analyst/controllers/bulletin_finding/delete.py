from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinFinding


class BulletinFindingDeleteController(AuditedDestroyController):
    queryset = BulletinFinding.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_FINDING_DELETED"
