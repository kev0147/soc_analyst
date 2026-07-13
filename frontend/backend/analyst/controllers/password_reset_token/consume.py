import hashlib

from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.models import PasswordResetToken
from analyst.serializers.password_reset_token import ConsumePasswordResetTokenSerializer


class PasswordResetTokenConsumeController(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ConsumePasswordResetTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token_hash = hashlib.sha256(serializer.validated_data["token"].encode()).hexdigest()
        try:
            token = PasswordResetToken.objects.select_related("user").get(
                token_hash=token_hash,
                used_at__isnull=True,
                expires_at__gt=timezone.now(),
            )
        except PasswordResetToken.DoesNotExist:
            return Response({"token": "Lien invalide ou expiré."}, status=status.HTTP_400_BAD_REQUEST)
        token.user.set_password(serializer.validated_data["password"])
        token.user.save(update_fields=("password", "updated_at"))
        token.used_at = timezone.now()
        token.save(update_fields=("used_at",))
        record_audit(request, "AUTH_PASSWORD_RESET_USED", token, {"user_id": token.user_id})
        return Response(status=status.HTTP_204_NO_CONTENT)
