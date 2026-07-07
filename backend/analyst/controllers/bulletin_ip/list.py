from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinIP
from analyst.serializers import BulletinIPSerializer


class BulletinIPListController(generics.ListAPIView):
    queryset = BulletinIP.objects.all()
    serializer_class = BulletinIPSerializer
    permission_classes = (IsAuthenticated,)
