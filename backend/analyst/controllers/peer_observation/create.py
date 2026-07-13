from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import PeerObservation
from analyst.serializers import PeerObservationSerializer


class PeerObservationCreateController(AuditedCreateController):
    queryset = PeerObservation.objects.all()
    serializer_class = PeerObservationSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "PEER_OBSERVATION_CREATED"
