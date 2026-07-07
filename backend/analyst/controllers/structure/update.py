from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Structure
from analyst.serializers import StructureSerializer


class StructureUpdateController(AuditedUpdateController):
    queryset = Structure.objects.all()
    serializer_class = StructureSerializer
    permission_classes = (IsAdmin,)
    audit_action = "STRUCTURE_UPDATED"
