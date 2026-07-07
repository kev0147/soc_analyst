from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Network
from analyst.serializers import NetworkSerializer


class NetworkUpdateController(AuditedUpdateController):
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsAdmin,)
    audit_action = "NETWORK_UPDATED"
