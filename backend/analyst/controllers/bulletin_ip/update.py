from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinIP
from analyst.serializers import BulletinIPSerializer


class BulletinIPUpdateController(AuditedUpdateController):
    queryset = BulletinIP.objects.all()
    serializer_class = BulletinIPSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_IP_UPDATED"
