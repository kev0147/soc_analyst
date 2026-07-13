from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinResponse
from analyst.serializers import BulletinResponseSerializer


class BulletinResponseCreateController(AuditedCreateController):
    queryset = BulletinResponse.objects.all()
    serializer_class = BulletinResponseSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RESPONSE_CREATED"
