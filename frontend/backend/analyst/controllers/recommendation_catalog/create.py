from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import RecommendationCatalog
from analyst.serializers import RecommendationCatalogSerializer


class RecommendationCatalogCreateController(AuditedCreateController):
    queryset = RecommendationCatalog.objects.all()
    serializer_class = RecommendationCatalogSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "RECOMMENDATION_CREATED"
