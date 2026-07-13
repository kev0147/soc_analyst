from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinTypeCatalog
from analyst.serializers import BulletinTypeCatalogSerializer


class BulletinTypeCatalogListController(generics.ListAPIView):
    queryset = BulletinTypeCatalog.objects.all()
    serializer_class = BulletinTypeCatalogSerializer
    permission_classes = (IsAuthenticated,)
