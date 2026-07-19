from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import ActivityCatalog


class ActivityCatalogDeleteController(DeactivateController):
    queryset = ActivityCatalog.objects.all()
    permission_classes = (IsAdmin,)
    audit_action = "ACTIVITY_DISABLED"
