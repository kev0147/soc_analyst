from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinTypeCatalog


class BulletinTypeCatalogDeleteController(DeactivateController):
    queryset = BulletinTypeCatalog.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "TYPE_DISABLED"
