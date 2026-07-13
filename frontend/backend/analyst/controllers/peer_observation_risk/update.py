from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import PeerObservationRisk
from analyst.serializers import PeerObservationRiskSerializer


class PeerObservationRiskUpdateController(AuditedUpdateController):
    queryset = PeerObservationRisk.objects.all()
    serializer_class = PeerObservationRiskSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "PEER_OBSERVATION_RISK_UPDATED"
