from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinFinding
from analyst.serializers import BulletinFindingSerializer


class BulletinFindingCreateController(AuditedCreateController):
    queryset = BulletinFinding.objects.all()
    serializer_class = BulletinFindingSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_FINDING_CREATED"
