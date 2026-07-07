from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinTypeCatalog
from analyst.serializers import BulletinTypeCatalogSerializer


class BulletinTypeCatalogCreateController(AuditedCreateController):
    queryset = BulletinTypeCatalog.objects.all()
    serializer_class = BulletinTypeCatalogSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "TYPE_CREATED"
