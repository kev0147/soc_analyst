from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.serializers.bulletin.serializer import BulletinCreateInputSerializer
from analyst.services.bulletins import find_duplicate_bulletins


class BulletinCheckDuplicateController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = BulletinCreateInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        duplicates = find_duplicate_bulletins(
            structure_id=data["structure"].id,
            ips=data["ips"],
            risk_ids=[risk.id for risk in data["risks"]],
        )
        record_audit(
            request,
            "BULLETIN_DUPLICATE_CHECKED",
            details={"structure_id": data["structure"].id, "duplicate_count": len(duplicates)},
        )
        return Response(
            {
                "has_duplicates": bool(duplicates),
                "duplicates": duplicates,
            },
            status=status.HTTP_200_OK,
        )
