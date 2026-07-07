from analyst.controllers.base import DeactivateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import Structure


class StructureDeleteController(DeactivateController):
    queryset = Structure.objects.all()
    permission_classes = (IsAdmin,)
    audit_action = "STRUCTURE_DISABLED"
