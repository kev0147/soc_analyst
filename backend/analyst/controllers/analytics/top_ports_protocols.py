from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.services.analytics import top_ports_protocols


class TopPortsProtocolsController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        result = top_ports_protocols(request.query_params)
        record_audit(request, "ANALYTICS_TOP_PORTS_PROTOCOLS_VIEWED", details={"filters": dict(request.query_params)})
        return Response(result)
