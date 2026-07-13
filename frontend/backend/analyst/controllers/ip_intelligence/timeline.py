from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.services.ip_intelligence import build_ip_timeline


class IPTimelineController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, ip):
        result = build_ip_timeline(ip, request.query_params)
        record_audit(
            request,
            "IP_TIMELINE_VIEWED",
            details={"ip": result["ip"], "filters": result["filters"], "counts": result["counts"]},
        )
        return Response(result)
