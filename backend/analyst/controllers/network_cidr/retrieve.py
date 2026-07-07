from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import NetworkCIDR
from analyst.serializers import NetworkCIDRSerializer


class NetworkCIDRRetrieveController(generics.RetrieveAPIView):
    queryset = NetworkCIDR.objects.all()
    serializer_class = NetworkCIDRSerializer
    permission_classes = (IsAuthenticated,)
