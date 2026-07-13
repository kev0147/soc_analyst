from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.services.peer_observations import sync_peer_observations


class PeerObservationSyncInputSerializer(serializers.Serializer):
    scope = serializers.ChoiceField(choices=("all_flows", "import"), default="all_flows")
    import_id = serializers.IntegerField(required=False, allow_null=True)


class PeerObservationSyncController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = PeerObservationSyncInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            result = sync_peer_observations(
                scope=data["scope"],
                import_id=data.get("import_id"),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        record_audit(request, "PEER_OBSERVATIONS_SYNCED", details=result)
        return Response(result, status=status.HTTP_202_ACCEPTED)
