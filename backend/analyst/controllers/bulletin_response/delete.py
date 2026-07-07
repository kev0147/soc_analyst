from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinResponse


class BulletinResponseDeleteController(AuditedDestroyController):
    queryset = BulletinResponse.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RESPONSE_DELETED"
