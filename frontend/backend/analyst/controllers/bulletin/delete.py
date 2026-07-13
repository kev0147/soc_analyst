from analyst.controllers.base import SoftDeleteBulletinController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Bulletin


class BulletinDeleteController(SoftDeleteBulletinController):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True)
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_DELETED"
