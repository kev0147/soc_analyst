from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import NetworkCIDR
from analyst.serializers import NetworkCIDRSerializer


class NetworkCIDRUpdateController(AuditedUpdateController):
    queryset = NetworkCIDR.objects.all()
    serializer_class = NetworkCIDRSerializer
    permission_classes = (IsAdmin,)
    audit_action = "NETWORK_CIDR_UPDATED"
