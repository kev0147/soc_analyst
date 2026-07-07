from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Bulletin
from analyst.serializers import BulletinSerializer


class BulletinRetrieveController(generics.RetrieveAPIView):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True)
    serializer_class = BulletinSerializer
    permission_classes = (IsAuthenticated,)
