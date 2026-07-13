from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Bulletin
from analyst.serializers import BulletinSerializer


class BulletinUpdateController(AuditedUpdateController):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True)
    serializer_class = BulletinSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_UPDATED"
