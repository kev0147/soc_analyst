from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Bulletin
from analyst.serializers.bulletin.serializer import BulletinCreateInputSerializer, BulletinSerializer
from analyst.services.bulletins import create_bulletin_with_links


class BulletinCreateController(APIView):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True)
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request):
        serializer = BulletinCreateInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        force_duplicate = serializer.validated_data.pop("force_duplicate", False)
        bulletin, duplicates = create_bulletin_with_links(
            data=serializer.validated_data,
            user=request.user,
            force_duplicate=force_duplicate,
        )
        if bulletin is None:
            return Response(
                {
                    "detail": "Un bulletin similaire existe déjà.",
                    "duplicate_policy": "same_structure_same_ips_roles_same_risks",
                    "duplicates": duplicates,
                    "can_force": True,
                },
                status=status.HTTP_409_CONFLICT,
            )

        record_audit(
            request,
            "BULLETIN_CREATED",
            bulletin,
            details={
                "forced_duplicate": bool(duplicates and force_duplicate),
                "duplicate_count": len(duplicates),
            },
        )
        response_status = status.HTTP_201_CREATED
        return Response(
            {
                "bulletin": BulletinSerializer(bulletin).data,
                "warnings": {
                    "duplicates": duplicates,
                    "forced_duplicate": bool(duplicates and force_duplicate),
                },
            },
            status=response_status,
        )
