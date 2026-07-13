from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdmin
from analyst.models import NetworkCIDR


class NetworkCIDRDeleteController(AuditedDestroyController):
    queryset = NetworkCIDR.objects.all()
    permission_classes = (IsAdmin,)
    audit_action = "NETWORK_CIDR_DELETED"
