from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.serializers.bulletin.serializer import BulletinAssistantDraftInputSerializer, BulletinSerializer
from analyst.services.bulletins import create_bulletin_from_findings


class BulletinAssistantCreateDraftController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = BulletinAssistantDraftInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        force_duplicate = data.pop("force_duplicate", False)
        bulletin, duplicates = create_bulletin_from_findings(
            data=data,
            user=request.user,
            force_duplicate=force_duplicate,
        )
        if bulletin is None:
            return Response(
                {
                    "detail": "Un bulletin similaire existe déjà.",
                    "duplicates": duplicates,
                    "can_force": True,
                },
                status=status.HTTP_409_CONFLICT,
            )

        record_audit(
            request,
            "BULLETIN_DRAFT_CREATED_FROM_ASSISTANT",
            bulletin,
            details={
                "ioc": data["risk_indicator"].name,
                "finding_count": bulletin.findings.count(),
                "forced_duplicate": bool(duplicates and force_duplicate),
            },
        )
        return Response(
            {
                "bulletin": BulletinSerializer(bulletin).data,
                "warnings": {"duplicates": duplicates},
            },
            status=status.HTTP_201_CREATED,
        )
