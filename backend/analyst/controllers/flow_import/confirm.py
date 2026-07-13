from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import FlowImport
from analyst.serializers import FlowImportSerializer
from analyst.services.imports import confirm_flow_import


class FlowImportConfirmInputSerializer(serializers.Serializer):
    import_id = serializers.IntegerField()


class FlowImportConfirmController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = FlowImportConfirmInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        flow_import = get_object_or_404(FlowImport, pk=serializer.validated_data["import_id"])
        try:
            confirmed = confirm_flow_import(flow_import)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        record_audit(
            request,
            "FLOW_IMPORT_CONFIRMED",
            confirmed,
            details={
                "status": confirmed.status,
                "total_rows": confirmed.total_rows,
                "accepted_rows": confirmed.accepted_rows,
                "rejected_rows": confirmed.rejected_rows,
            },
        )
        return Response(FlowImportSerializer(confirmed).data)
