from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import PeerObservation


class PeerObservationDeleteController(AuditedDestroyController):
    queryset = PeerObservation.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "PEER_OBSERVATION_DELETED"
