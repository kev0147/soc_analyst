from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import ActivityCatalog
from analyst.serializers import ActivityCatalogSerializer


class ActivityCatalogUpdateController(AuditedUpdateController):
    queryset = ActivityCatalog.objects.all()
    serializer_class = ActivityCatalogSerializer
    permission_classes = (IsAdmin,)
    audit_action = "ACTIVITY_UPDATED"
