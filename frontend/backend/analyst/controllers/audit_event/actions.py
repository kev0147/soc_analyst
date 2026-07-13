from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdmin
from analyst.services.security import audit_action_catalog


class AuditEventActionsController(APIView):
    permission_classes = (IsAdmin,)

    def get(self, request):
        record_audit(request, "AUDIT_EVENTS_VIEWED", details={"view": "actions"})
        return Response({"actions": audit_action_catalog()})
