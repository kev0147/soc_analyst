from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinRecommendation
from analyst.serializers import BulletinRecommendationSerializer


class BulletinRecommendationRetrieveController(generics.RetrieveAPIView):
    queryset = BulletinRecommendation.objects.all()
    serializer_class = BulletinRecommendationSerializer
    permission_classes = (IsAuthenticated,)
