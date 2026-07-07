import hashlib
import secrets
from datetime import timedelta

from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdmin
from analyst.models import PasswordResetToken, User


class PasswordResetTokenCreateController(APIView):
    permission_classes = (IsAdmin,)

    def post(self, request):
        try:
            user = User.objects.get(pk=request.data.get("user"))
        except User.DoesNotExist:
            return Response({"user": "Utilisateur introuvable."}, status=status.HTTP_400_BAD_REQUEST)
        raw_token = secrets.token_urlsafe(32)
        token = PasswordResetToken.objects.create(
            user=user,
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            created_by=request.user,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        record_audit(request, "AUTH_PASSWORD_RESET_CREATED", token, {"user_id": user.pk})
        return Response(
            {"id": token.pk, "user": user.pk, "token": raw_token, "expires_at": token.expires_at},
            status=status.HTTP_201_CREATED,
        )
