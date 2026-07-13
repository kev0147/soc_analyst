from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Network


class NetworkDeleteController(DeactivateController):
    queryset = Network.objects.all()
    permission_classes = (IsAdmin,)
    audit_action = "NETWORK_DISABLED"
