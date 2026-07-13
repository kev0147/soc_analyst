from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RecommendationCatalog


class RecommendationCatalogDeleteController(DeactivateController):
    queryset = RecommendationCatalog.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RECOMMENDATION_DISABLED"
