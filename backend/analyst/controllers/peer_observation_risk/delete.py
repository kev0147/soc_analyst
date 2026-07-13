from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import PeerObservationRisk


class PeerObservationRiskDeleteController(AuditedDestroyController):
    queryset = PeerObservationRisk.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "PEER_OBSERVATION_RISK_DELETED"
