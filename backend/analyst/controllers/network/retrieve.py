from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Network
from analyst.serializers import NetworkSerializer


class NetworkRetrieveController(generics.RetrieveAPIView):
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    permission_classes = (IsAuthenticated,)
