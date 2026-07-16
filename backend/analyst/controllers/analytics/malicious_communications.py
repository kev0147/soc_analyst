from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.services.analytics import malicious_communications


class MaliciousCommunicationsController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        result = malicious_communications(request.query_params)
        record_audit(
            request,
            "MALICIOUS_COMMUNICATIONS_ANALYZED",
            details={"filters": dict(request.query_params), "result_count": result["count"]},
        )
        return Response(result)
