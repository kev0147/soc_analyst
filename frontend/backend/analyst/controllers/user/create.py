from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import User
from analyst.serializers import UserSerializer


class UserCreateController(AuditedCreateController):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAdmin,)
    audit_action = "USER_CREATED"
