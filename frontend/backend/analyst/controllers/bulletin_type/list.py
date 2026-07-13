from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinType
from analyst.serializers import BulletinTypeSerializer


class BulletinTypeListController(generics.ListAPIView):
    queryset = BulletinType.objects.all()
    serializer_class = BulletinTypeSerializer
    permission_classes = (IsAuthenticated,)
