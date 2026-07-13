from rest_framework import generics

from analyst.controllers.permissions import IsAdmin
from analyst.models import PasswordResetToken
from analyst.serializers import PasswordResetTokenSerializer


class PasswordResetTokenRetrieveController(generics.RetrieveAPIView):
    queryset = PasswordResetToken.objects.all()
    serializer_class = PasswordResetTokenSerializer
    permission_classes = (IsAdmin,)

