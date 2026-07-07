from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinResponse
from analyst.serializers import BulletinResponseSerializer


class BulletinResponseListController(generics.ListAPIView):
    queryset = BulletinResponse.objects.all()
    serializer_class = BulletinResponseSerializer
    permission_classes = (IsAuthenticated,)
