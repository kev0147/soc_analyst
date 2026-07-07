from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import User
from analyst.serializers import UserSerializer


class UserListController(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
