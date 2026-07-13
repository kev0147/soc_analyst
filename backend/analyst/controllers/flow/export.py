from django.http import StreamingHttpResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.models import Flow
from analyst.services.flows import apply_flow_filters, flow_export_rows


class FlowExportController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        queryset = apply_flow_filters(Flow.objects.all(), request.query_params)
        record_audit(request, "FLOW_EXPORTED", details={"filters": dict(request.query_params)})
        response = StreamingHttpResponse(
            flow_export_rows(queryset),
            content_type="text/csv; charset=utf-8",
        )
        response["Content-Disposition"] = 'attachment; filename="flows_export.csv"'
        return response
