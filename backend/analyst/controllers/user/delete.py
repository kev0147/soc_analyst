from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import User


class UserDeleteController(DeactivateController):
    queryset = User.objects.all()
    permission_classes = (IsAdmin,)
    audit_action = "USER_DISABLED"
