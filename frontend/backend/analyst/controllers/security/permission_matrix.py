from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.services.security import permission_matrix


class PermissionMatrixController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        record_audit(request, "SECURITY_PERMISSION_MATRIX_VIEWED")
        return Response({"roles": permission_matrix()})
