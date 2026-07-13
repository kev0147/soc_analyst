from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.services.analytics import build_dashboard_overview


class DashboardOverviewController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        result = build_dashboard_overview(request.query_params)
        record_audit(request, "DASHBOARD_OVERVIEW_VIEWED", details={"scope": result["scope"]})
        return Response(result)
