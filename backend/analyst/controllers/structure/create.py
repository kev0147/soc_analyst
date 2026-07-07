from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Structure
from analyst.serializers import StructureSerializer


class StructureCreateController(AuditedCreateController):
    queryset = Structure.objects.all()
    serializer_class = StructureSerializer
    permission_classes = (IsAdmin,)
    audit_action = "STRUCTURE_CREATED"
