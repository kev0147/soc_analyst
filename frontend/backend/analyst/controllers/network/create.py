from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Network
from analyst.serializers import NetworkSerializer


class NetworkCreateController(AuditedCreateController):
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsAdmin,)
    audit_action = "NETWORK_CREATED"
