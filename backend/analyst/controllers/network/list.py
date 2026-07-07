from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Network
from analyst.serializers import NetworkSerializer


class NetworkListController(generics.ListAPIView):
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsAuthenticated,)
