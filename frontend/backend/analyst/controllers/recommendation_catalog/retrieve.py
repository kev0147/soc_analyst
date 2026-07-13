from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import RecommendationCatalog
from analyst.serializers import RecommendationCatalogSerializer


class RecommendationCatalogRetrieveController(generics.RetrieveAPIView):
    queryset = RecommendationCatalog.objects.all()
    serializer_class = RecommendationCatalogSerializer
    permission_classes = (IsAuthenticated,)
