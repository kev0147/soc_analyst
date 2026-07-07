from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import User
from analyst.serializers import UserSerializer


class UserRetrieveController(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
