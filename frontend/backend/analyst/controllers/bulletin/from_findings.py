from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.serializers.bulletin.serializer import BulletinFromFindingsInputSerializer, BulletinSerializer
from analyst.services.bulletins import create_bulletin_from_findings


class BulletinFromFindingsController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = BulletinFromFindingsInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        force_duplicate = serializer.validated_data.pop("force_duplicate", False)
        bulletin, duplicates = create_bulletin_from_findings(
            data=serializer.validated_data,
            user=request.user,
            force_duplicate=force_duplicate,
        )
        if bulletin is None:
            return Response(
                {
                    "detail": "Un bulletin similaire existe déjà.",
                    "duplicate_policy": "same_structure_same_peer_observations_same_risk_profiles",
                    "duplicates": duplicates,
                    "can_force": True,
                },
                status=status.HTTP_409_CONFLICT,
            )

        record_audit(
            request,
            "BULLETIN_CREATED_FROM_FINDINGS",
            bulletin,
            details={
                "forced_duplicate": bool(duplicates and force_duplicate),
                "duplicate_count": len(duplicates),
                "finding_count": bulletin.findings.count(),
            },
        )
        return Response(
            {
                "bulletin": BulletinSerializer(bulletin).data,
                "warnings": {
                    "duplicates": duplicates,
                    "forced_duplicate": bool(duplicates and force_duplicate),
                },
            },
            status=status.HTTP_201_CREATED,
        )
