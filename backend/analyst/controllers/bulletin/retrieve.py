from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Bulletin
from analyst.serializers import BulletinSerializer


class BulletinRetrieveController(generics.RetrieveAPIView):
    queryset = Bulletin.objects.filter(deleted_at__isnull=True).select_related("structure").prefetch_related(
        "ip_addresses",
        "risk_links__risk",
        "activity_links__activity",
        "recommendation_links__recommendation",
        "findings",
    )
    serializer_class = BulletinSerializer
    permission_classes = (IsAuthenticated,)
