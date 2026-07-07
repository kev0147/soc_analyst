from rest_framework import generics

from analyst.controllers.permissions import IsAdmin
from analyst.models import PasswordResetToken
from analyst.serializers import PasswordResetTokenSerializer


class PasswordResetTokenListController(generics.ListAPIView):
    queryset = PasswordResetToken.objects.all()
    serializer_class = PasswordResetTokenSerializer
    permission_classes = (IsAdmin,)

