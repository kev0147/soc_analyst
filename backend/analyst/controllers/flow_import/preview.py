from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Network
from analyst.services.imports import preview_flow_import_upload


class FlowImportPreviewInputSerializer(serializers.Serializer):
    network_id = serializers.IntegerField()
    file = serializers.FileField()


class FlowImportPreviewController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = FlowImportPreviewInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        network = get_object_or_404(Network, pk=serializer.validated_data["network_id"])
        try:
            result = preview_flow_import_upload(
                uploaded_file=serializer.validated_data["file"],
                network=network,
                user=request.user,
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        record_audit(
            request,
            "FLOW_IMPORT_PREVIEWED",
            details={
                "import_id": result["import_id"],
                "network_id": network.id,
                "is_valid": result["is_valid"],
            },
        )
        return Response(result, status=status.HTTP_201_CREATED)
