from pathlib import Path

from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import FlowImport


class FlowImportDownloadRejectionsController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def get(self, request, pk):
        flow_import = get_object_or_404(FlowImport, pk=pk)
        if not flow_import.rejection_report_path:
            return Response({"detail": "Aucun rapport de rejet pour cet import."}, status=status.HTTP_404_NOT_FOUND)

        path = Path(flow_import.rejection_report_path)
        if not path.exists():
            return Response({"detail": "Le rapport de rejet est introuvable sur le disque."}, status=status.HTTP_404_NOT_FOUND)

        record_audit(request, "FLOW_IMPORT_REJECTIONS_DOWNLOADED", flow_import)
        return FileResponse(
            path.open("rb"),
            as_attachment=True,
            filename=f"flow_import_{flow_import.id}_rejections.csv",
            content_type="text/csv",
        )
