from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinType
from analyst.serializers import BulletinTypeSerializer


class BulletinTypeCreateController(AuditedCreateController):
    queryset = BulletinType.objects.all()
    serializer_class = BulletinTypeSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_TYPE_CREATED"
