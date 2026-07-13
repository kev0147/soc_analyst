from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import RiskProfile
from analyst.serializers import RiskProfileSerializer


class RiskProfileRetrieveController(generics.RetrieveAPIView):
    queryset = RiskProfile.objects.all()
    serializer_class = RiskProfileSerializer
    permission_classes = (IsAuthenticated,)
