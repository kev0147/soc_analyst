from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinFinding
from analyst.serializers import BulletinFindingSerializer


class BulletinFindingUpdateController(AuditedUpdateController):
    queryset = BulletinFinding.objects.all()
    serializer_class = BulletinFindingSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_FINDING_UPDATED"
