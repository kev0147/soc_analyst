from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinRecommendation
from analyst.serializers import BulletinRecommendationSerializer


class BulletinRecommendationCreateController(AuditedCreateController):
    queryset = BulletinRecommendation.objects.all()
    serializer_class = BulletinRecommendationSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_RECOMMENDATION_CREATED"
