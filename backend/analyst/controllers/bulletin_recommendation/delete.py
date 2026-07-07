from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinRecommendation


class BulletinRecommendationDeleteController(AuditedDestroyController):
    queryset = BulletinRecommendation.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RECOMMENDATION_DELETED"
